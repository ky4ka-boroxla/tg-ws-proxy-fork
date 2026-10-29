use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use tokio::task::JoinHandle;

use crate::config::ProxyConfig;
use crate::stats::{inc, stats};
use crate::utils::{dc_default_ip, ws_domains, DC_DEFAULT_IPS, WS_PATH, WS_PATH_TEST};
use crate::ws::{ConnectOptions, RawWebSocket, WsError};

pub trait WsDialer: Send + Sync + 'static {
    fn dial<'a>(
        &'a self,
        host: &'a str,
        domain: &'a str,
        timeout: Duration,
        path: &'a str,
        options: ConnectOptions,
    ) -> BoxFuture<'a, Result<RawWebSocket, WsError>>;
}

pub struct RealDialer;

impl WsDialer for RealDialer {
    fn dial<'a>(
        &'a self,
        host: &'a str,
        domain: &'a str,
        timeout: Duration,
        path: &'a str,
        options: ConnectOptions,
    ) -> BoxFuture<'a, Result<RawWebSocket, WsError>> {
        Box::pin(async move { RawWebSocket::connect(host, domain, timeout, path, &options).await })
    }
}

pub type PoolKey = (i32, bool, bool);

const WS_POOL_MAX_AGE: Duration = Duration::from_secs(120);
const WS_POOL_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const REFILL_BACKOFF_INITIAL: f64 = 1.0;
const REFILL_BACKOFF_MAX: f64 = 3600.0;
const FRONTING_SNI: &str = "sprinthost.ru";

fn key_tag(key: &PoolKey) -> String {
    format!("DC{}{}{}", key.0, if key.2 { "t" } else { "" }, if key.1 { "m" } else { "" })
}

#[derive(Default)]
struct WsPoolState {
    idle: HashMap<PoolKey, VecDeque<(RawWebSocket, Instant)>>,
    refilling: HashMap<PoolKey, (u64, JoinHandle<()>)>,
    rotating: HashMap<PoolKey, (u64, JoinHandle<()>)>,
    refill_failures: HashMap<PoolKey, u32>,
    refill_after: HashMap<PoolKey, Instant>,
    next_generation: u64,
}

pub struct WsPool {
    config: Arc<ProxyConfig>,
    dialer: Arc<dyn WsDialer>,
    state: Mutex<WsPoolState>,
    try_fronting_first: AtomicBool,
}

fn spawn_close(ws: RawWebSocket) {
    tokio::spawn(async move { ws.close().await });
}

impl WsPool {
    pub fn new(config: Arc<ProxyConfig>) -> Arc<Self> {
        Self::with_dialer(config, Arc::new(RealDialer))
    }

    pub fn with_dialer(config: Arc<ProxyConfig>, dialer: Arc<dyn WsDialer>) -> Arc<Self> {
        Arc::new(Self {
            config,
            dialer,
            state: Mutex::new(WsPoolState::default()),
            try_fronting_first: AtomicBool::new(false),
        })
    }

    pub fn idle_count(&self, key: &PoolKey) -> usize {
        self.state.lock().idle.get(key).map(|b| b.len()).unwrap_or(0)
    }

    pub fn get(self: &Arc<Self>, dc: i32, is_media: bool, is_test_dc: bool) -> Option<RawWebSocket> {
        let target_ip = self.config.dc_redirects.get(&dc)?.clone();
        if self.config.pool_size == 0 {
            return None;
        }
        let key = (dc, is_media, is_test_dc);
        let domains = ws_domains(dc, is_media);
        let now = Instant::now();
        let mut stale = Vec::new();
        let mut hit = None;
        {
            let mut state = self.state.lock();
            let bucket = state.idle.entry(key).or_default();
            while let Some((ws, created)) = bucket.pop_front() {
                if now.duration_since(created) >= WS_POOL_MAX_AGE || !ws.is_alive() {
                    stale.push(ws);
                    continue;
                }
                log::debug!(
                    "WS pool hit {} (age={:.1}s, left={})",
                    key_tag(&key),
                    now.duration_since(created).as_secs_f64(),
                    bucket.len()
                );
                hit = Some(ws);
                break;
            }
        }
        for ws in stale {
            spawn_close(ws);
        }
        if hit.is_some() {
            inc(&stats().pool_hits);
        } else {
            inc(&stats().pool_misses);
        }
        self.schedule_refill(key, target_ip, domains);
        hit
    }

    fn schedule_refill(self: &Arc<Self>, key: PoolKey, target_ip: String, domains: Vec<String>) {
        if self.config.pool_size == 0 {
            return;
        }
        self.schedule_rotation(key, target_ip.clone(), domains.clone());
        let mut state = self.state.lock();
        if state.refilling.contains_key(&key) {
            return;
        }
        if let Some(after) = state.refill_after.get(&key) {
            if Instant::now() < *after {
                return;
            }
        }
        state.next_generation += 1;
        let generation = state.next_generation;
        let pool = self.clone();
        let handle = tokio::spawn(async move { pool.refill(key, target_ip, domains, generation).await });
        state.refilling.insert(key, (generation, handle));
    }

    fn schedule_rotation(self: &Arc<Self>, key: PoolKey, target_ip: String, domains: Vec<String>) {
        let mut state = self.state.lock();
        if state.rotating.contains_key(&key) {
            return;
        }
        state.next_generation += 1;
        let generation = state.next_generation;
        let pool = self.clone();
        let handle = tokio::spawn(async move { pool.rotate(key, target_ip, domains, generation).await });
        state.rotating.insert(key, (generation, handle));
    }

    async fn refill(self: Arc<Self>, key: PoolKey, target_ip: String, domains: Vec<String>, generation: u64) {
        let needed = {
            let state = self.state.lock();
            let have = state.idle.get(&key).map(|b| b.len()).unwrap_or(0);
            self.config.pool_size.saturating_sub(have)
        };
        let finish = |pool: &Arc<Self>| {
            let mut state = pool.state.lock();
            if state.refilling.get(&key).map(|(g, _)| *g) == Some(generation) {
                state.refilling.remove(&key);
            }
        };
        if needed == 0 {
            finish(&self);
            return;
        }
        let path = if key.2 { WS_PATH_TEST } else { WS_PATH };
        let mut attempts = FuturesUnordered::new();
        for _ in 0..needed {
            attempts.push(self.connect_one(&target_ip, &domains, path));
        }
        let mut connected = 0usize;
        while let Some(result) = attempts.next().await {
            let Some(ws) = result else { continue };
            let mut state = self.state.lock();
            if state.refilling.get(&key).map(|(g, _)| *g) != Some(generation) {
                drop(state);
                spawn_close(ws);
                return;
            }
            state.idle.entry(key).or_default().push_back((ws, Instant::now()));
            connected += 1;
        }
        drop(attempts);
        {
            let mut state = self.state.lock();
            if connected > 0 {
                state.refill_failures.remove(&key);
                state.refill_after.remove(&key);
            } else {
                let failures = state.refill_failures.get(&key).copied().unwrap_or(0) + 1;
                state.refill_failures.insert(key, failures);
                let delay = (REFILL_BACKOFF_INITIAL * 2f64.powi(failures.saturating_sub(1).min(12) as i32))
                    .min(REFILL_BACKOFF_MAX);
                state.refill_after.insert(key, Instant::now() + Duration::from_secs_f64(delay));
                log::info!("WS pool refill failed for {}, retry in {:.0}s", key_tag(&key), delay);
            }
            log::debug!(
                "WS pool refilled {}: {} ready",
                key_tag(&key),
                state.idle.get(&key).map(|b| b.len()).unwrap_or(0)
            );
        }
        finish(&self);
    }

    async fn rotate(self: Arc<Self>, key: PoolKey, target_ip: String, domains: Vec<String>, generation: u64) {
        while self.config.pool_size > 0 {
            let now = Instant::now();
            let mut expired = Vec::new();
            let (len, wake_at) = {
                let mut state = self.state.lock();
                let bucket = state.idle.entry(key).or_default();
                let mut ready = VecDeque::new();
                while let Some((ws, created)) = bucket.pop_front() {
                    if now.duration_since(created) >= WS_POOL_MAX_AGE || !ws.is_alive() {
                        expired.push(ws);
                    } else {
                        ready.push_back((ws, created));
                    }
                }
                bucket.extend(ready);
                let len = bucket.len();
                let mut wake_at = now + WS_POOL_CHECK_INTERVAL;
                if let Some(oldest) = bucket.iter().map(|(_, c)| *c + WS_POOL_MAX_AGE).min() {
                    wake_at = wake_at.min(oldest);
                }
                if !state.refilling.contains_key(&key) {
                    if let Some(after) = state.refill_after.get(&key) {
                        if *after > now {
                            wake_at = wake_at.min(*after);
                        }
                    }
                }
                (len, wake_at)
            };
            if !expired.is_empty() {
                log::debug!(
                    "WS pool rotated {}: {} stale, {} ready",
                    key_tag(&key),
                    expired.len(),
                    len
                );
                for ws in expired {
                    spawn_close(ws);
                }
            }
            if len < self.config.pool_size {
                self.schedule_refill(key, target_ip.clone(), domains.clone());
            }
            tokio::time::sleep_until(wake_at.max(Instant::now())).await;
        }
        let mut state = self.state.lock();
        if state.rotating.get(&key).map(|(g, _)| *g) == Some(generation) {
            state.rotating.remove(&key);
        }
    }

    async fn connect_one(&self, target_ip: &str, domains: &[String], path: &str) -> Option<RawWebSocket> {
        for domain in domains {
            let modes: [bool; 2] =
                if self.try_fronting_first.load(Ordering::Relaxed) { [true, false] } else { [false, true] };
            for fronted in modes {
                let options = ConnectOptions {
                    sni: fronted.then(|| FRONTING_SNI.to_string()),
                    secure: true,
                    port: None,
                    buffer_size: self.config.buffer_size,
                };
                let timeout = Duration::from_secs(if fronted { 7 } else { 8 });
                match self.dialer.dial(target_ip, domain, timeout, path, options).await {
                    Ok(ws) => {
                        self.try_fronting_first.store(fronted, Ordering::Relaxed);
                        if fronted {
                            inc(&stats().connections_fronting);
                        }
                        log::debug!("WS pool connected {domain}{path} via {target_ip} (fronting={fronted})");
                        return Some(ws);
                    }
                    Err(err) => {
                        inc(&stats().ws_errors);
                        log::debug!("WS pool connect {domain}{path} via {target_ip} (fronting={fronted}): {err:?}");
                    }
                }
            }
        }
        None
    }

    pub fn warmup(self: &Arc<Self>) {
        for (dc, target_ip) in &self.config.dc_redirects {
            for is_media in [false, true] {
                let key = (*dc, is_media, self.config.force_test_dc);
                self.schedule_refill(key, target_ip.clone(), ws_domains(*dc, is_media));
            }
        }
        log::info!("WS pool warmup started for {} DC(s)", self.config.dc_redirects.len());
    }

    pub fn reset(&self) -> Vec<JoinHandle<()>> {
        let mut handles = Vec::new();
        let mut closing = Vec::new();
        {
            let mut state = self.state.lock();
            for (_, (_, handle)) in state.rotating.drain() {
                handle.abort();
                handles.push(handle);
            }
            for (_, (_, handle)) in state.refilling.drain() {
                handle.abort();
                handles.push(handle);
            }
            for (_, bucket) in state.idle.drain() {
                closing.extend(bucket.into_iter().map(|(ws, _)| ws));
            }
            state.refill_failures.clear();
            state.refill_after.clear();
        }
        self.try_fronting_first.store(false, Ordering::Relaxed);
        for ws in closing {
            spawn_close(ws);
        }
        handles
    }

    pub async fn close(&self) {
        let handles = self.reset();
        for handle in handles {
            let _ = handle.await;
        }
    }
}

const CF_POOL_MAX_AGE: Duration = Duration::from_secs(100);
const CF_PER_DC_LIMIT: usize = 1;

#[derive(Default)]
struct CfPoolState {
    idle: HashMap<i32, VecDeque<(RawWebSocket, Instant, String)>>,
    refilling: HashMap<i32, (u64, JoinHandle<()>)>,
    next_generation: u64,
}

pub struct CfWorkerPool {
    config: Arc<ProxyConfig>,
    dialer: Arc<dyn WsDialer>,
    state: Mutex<CfPoolState>,
}

pub fn worker_path(dst: &str, dc: i32) -> String {
    format!("/apiws?dst={}&dc={}", dst, dc)
}

impl CfWorkerPool {
    pub fn new(config: Arc<ProxyConfig>) -> Arc<Self> {
        Self::with_dialer(config, Arc::new(RealDialer))
    }

    pub fn with_dialer(config: Arc<ProxyConfig>, dialer: Arc<dyn WsDialer>) -> Arc<Self> {
        Arc::new(Self { config, dialer, state: Mutex::new(CfPoolState::default()) })
    }

    pub fn idle_count(&self, dc: i32) -> usize {
        self.state.lock().idle.get(&dc).map(|b| b.len()).unwrap_or(0)
    }

    pub fn get(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: &str,
        worker_domains: &[String],
    ) -> Option<(RawWebSocket, String)> {
        let now = Instant::now();
        let mut stale = Vec::new();
        let mut hit = None;
        {
            let mut state = self.state.lock();
            let bucket = state.idle.entry(dc).or_default();
            while let Some((ws, created, domain)) = bucket.pop_front() {
                if now.duration_since(created) > CF_POOL_MAX_AGE || !ws.is_alive() {
                    stale.push(ws);
                    continue;
                }
                hit = Some((ws, domain));
                break;
            }
        }
        for ws in stale {
            spawn_close(ws);
        }
        if let Some((_, domain)) = &hit {
            inc(&stats().cf_pool_hits);
            log::debug!("CF worker pool hit DC{dc} via {domain}");
            self.schedule_refill(dc, fallback_dst.to_string(), worker_domains.to_vec());
        } else {
            inc(&stats().cf_pool_misses);
        }
        hit
    }

    fn schedule_refill(self: &Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>) {
        let mut state = self.state.lock();
        if state.refilling.contains_key(&dc) {
            return;
        }
        state.next_generation += 1;
        let generation = state.next_generation;
        let pool = self.clone();
        let handle = tokio::spawn(async move { pool.refill(dc, fallback_dst, worker_domains, generation).await });
        state.refilling.insert(dc, (generation, handle));
    }

    async fn refill(self: Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>, generation: u64) {
        let target = self.config.pool_size.min(CF_PER_DC_LIMIT);
        let needed = {
            let state = self.state.lock();
            target.saturating_sub(state.idle.get(&dc).map(|b| b.len()).unwrap_or(0))
        };
        for _ in 0..needed {
            let Some((ws, domain)) = self.connect_one(&worker_domains, &fallback_dst, dc).await else {
                break;
            };
            let mut state = self.state.lock();
            if state.refilling.get(&dc).map(|(g, _)| *g) != Some(generation) {
                drop(state);
                spawn_close(ws);
                return;
            }
            state.idle.entry(dc).or_default().push_back((ws, Instant::now(), domain));
        }
        let mut state = self.state.lock();
        log::debug!(
            "CF worker pool refilled DC{dc}: {} ready",
            state.idle.get(&dc).map(|b| b.len()).unwrap_or(0)
        );
        if state.refilling.get(&dc).map(|(g, _)| *g) == Some(generation) {
            state.refilling.remove(&dc);
        }
    }

    async fn connect_one(
        &self,
        worker_domains: &[String],
        fallback_dst: &str,
        dc: i32,
    ) -> Option<(RawWebSocket, String)> {
        let path = worker_path(fallback_dst, dc);
        for domain in self.available_domains(worker_domains) {
            let options = ConnectOptions {
                sni: None,
                secure: !self.config.disable_secure,
                port: None,
                buffer_size: self.config.buffer_size,
            };
            match self.dialer.dial(&domain, &domain, Duration::from_secs(8), &path, options).await {
                Ok(ws) => return Some((ws, domain)),
                Err(err) => self.report_failure(&domain, &err),
            }
        }
        None
    }

    pub fn available_domains(&self, worker_domains: &[String]) -> Vec<String> {
        let mut domains: Vec<String> = Vec::new();
        for domain in worker_domains {
            if !domains.contains(domain) {
                domains.push(domain.clone());
            }
        }
        domains.shuffle(&mut rand::thread_rng());
        domains
    }

    pub fn report_failure(&self, _worker_domain: &str, _error: &WsError) {}

    pub fn warmup(self: &Arc<Self>) {
        let fallbacks: Vec<(i32, &str)> = DC_DEFAULT_IPS
            .iter()
            .filter(|(dc, _)| !self.config.dc_redirects.contains_key(dc))
            .map(|(dc, ip)| (*dc, *ip))
            .collect();
        if fallbacks.is_empty() || self.config.cfproxy_worker_domains.is_empty() {
            return;
        }
        for (dc, ip) in &fallbacks {
            self.schedule_refill(*dc, ip.to_string(), self.config.cfproxy_worker_domains.clone());
        }
        log::info!("CF worker pool warmup started for {} DC(s)", fallbacks.len());
    }

    pub fn reset(&self) -> Vec<JoinHandle<()>> {
        let mut handles = Vec::new();
        let mut closing = Vec::new();
        {
            let mut state = self.state.lock();
            for (_, (_, handle)) in state.refilling.drain() {
                handle.abort();
                handles.push(handle);
            }
            for (_, bucket) in state.idle.drain() {
                closing.extend(bucket.into_iter().map(|(ws, _, _)| ws));
            }
        }
        for ws in closing {
            spawn_close(ws);
        }
        handles
    }

    pub async fn close(&self) {
        for handle in self.reset() {
            let _ = handle.await;
        }
    }
}

pub fn fallback_dst_for(dc: i32) -> Option<&'static str> {
    dc_default_ip(dc)
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::duplex;

    pub type DialLog = Arc<Mutex<Vec<(String, String, String, bool)>>>;

    pub struct FakeDialer {
        pub log: DialLog,
        pub fail_when: Box<dyn Fn(&str, bool) -> bool + Send + Sync>,
        pub delay: Duration,
        pub calls: AtomicUsize,
        pub keep_peers: Mutex<Vec<tokio::io::DuplexStream>>,
    }

    impl FakeDialer {
        pub fn new(fail_when: impl Fn(&str, bool) -> bool + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self {
                log: Arc::new(Mutex::new(Vec::new())),
                fail_when: Box::new(fail_when),
                delay: Duration::ZERO,
                calls: AtomicUsize::new(0),
                keep_peers: Mutex::new(Vec::new()),
            })
        }
    }

    impl WsDialer for FakeDialer {
        fn dial<'a>(
            &'a self,
            host: &'a str,
            domain: &'a str,
            _timeout: Duration,
            path: &'a str,
            options: ConnectOptions,
        ) -> BoxFuture<'a, Result<RawWebSocket, WsError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.log.lock().push((host.to_string(), domain.to_string(), path.to_string(), options.sni.is_some()));
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                if (self.fail_when)(domain, options.sni.is_some()) {
                    return Err(WsError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused")));
                }
                let (client, server) = duplex(4096);
                self.keep_peers.lock().push(server);
                let (r, w) = tokio::io::split(client);
                Ok(RawWebSocket::from_parts(Box::new(r), Box::new(w)))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn config(pool_size: usize) -> Arc<ProxyConfig> {
        let mut cfg = ProxyConfig::default();
        cfg.pool_size = pool_size;
        Arc::new(cfg)
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn regular_sessions_never_use_media_domain() {
        let dialer = FakeDialer::new(|_, _| false);
        let pool = WsPool::with_dialer(config(2), dialer.clone());
        assert!(pool.get(2, false, false).is_none());
        settle().await;
        let log = dialer.log.lock();
        assert!(!log.is_empty());
        assert!(log.iter().all(|(_, domain, _, _)| domain == "kws2.web.telegram.org"));
        assert!(log.iter().all(|(host, _, path, _)| host == "149.154.167.220" && path == WS_PATH));
    }

    #[tokio::test]
    async fn media_tries_regular_domain_after_both_modes_fail() {
        let dialer = FakeDialer::new(|domain, _| domain == "kws2-1.web.telegram.org");
        let pool = WsPool::with_dialer(config(1), dialer.clone());
        pool.get(2, true, false);
        settle().await;
        let log = dialer.log.lock();
        let domains: Vec<&str> = log.iter().map(|(_, d, _, _)| d.as_str()).collect();
        assert_eq!(
            domains,
            vec![
                "kws2-1.web.telegram.org",
                "kws2-1.web.telegram.org",
                "kws2.web.telegram.org"
            ]
        );
        drop(log);
        assert_eq!(pool.idle_count(&(2, true, false)), 1);
    }

    #[tokio::test]
    async fn fronting_preference_follows_last_success() {
        let dialer = FakeDialer::new(|_, fronted| !fronted);
        let pool = WsPool::with_dialer(config(1), dialer.clone());
        pool.get(2, false, false);
        settle().await;
        assert_eq!(pool.idle_count(&(2, false, false)), 1);
        assert!(pool.try_fronting_first.load(Ordering::Relaxed));
        let first_fronted = dialer.log.lock().iter().map(|e| e.3).collect::<Vec<_>>();
        assert_eq!(first_fronted, vec![false, true]);
        stats().reset();
        let hit = pool.get(2, false, false);
        assert!(hit.is_some());
        settle().await;
        let modes = dialer.log.lock().iter().map(|e| e.3).collect::<Vec<_>>();
        assert_eq!(modes[2], true);
    }

    #[tokio::test]
    async fn miss_returns_immediately_and_starts_only_one_refill() {
        let mut dialer = FakeDialer::new(|_, _| false);
        Arc::get_mut(&mut dialer).unwrap().delay = Duration::from_millis(80);
        let pool = WsPool::with_dialer(config(2), dialer.clone());
        let started = Instant::now();
        assert!(pool.get(2, false, false).is_none());
        assert!(pool.get(2, false, false).is_none());
        assert!(pool.get(2, false, false).is_none());
        assert!(started.elapsed() < Duration::from_millis(60));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(dialer.calls.load(Ordering::SeqCst), 2);
        assert_eq!(pool.idle_count(&(2, false, false)), 2);
    }

    #[tokio::test]
    async fn zero_size_and_unconfigured_dc_do_not_connect() {
        let dialer = FakeDialer::new(|_, _| false);
        let pool = WsPool::with_dialer(config(0), dialer.clone());
        assert!(pool.get(2, false, false).is_none());
        let pool = WsPool::with_dialer(config(2), dialer.clone());
        assert!(pool.get(1, false, false).is_none());
        settle().await;
        assert_eq!(dialer.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_dc_has_separate_pool_and_path() {
        let dialer = FakeDialer::new(|_, _| false);
        let pool = WsPool::with_dialer(config(1), dialer.clone());
        pool.get(2, false, true);
        settle().await;
        assert_eq!(dialer.log.lock()[0].2, WS_PATH_TEST);
        assert_eq!(pool.idle_count(&(2, false, true)), 1);
        assert_eq!(pool.idle_count(&(2, false, false)), 0);
        assert!(pool.get(2, false, false).is_none());
        assert!(pool.get(2, false, true).is_some());
    }

    #[tokio::test]
    async fn hit_takes_connection_and_refills() {
        let dialer = FakeDialer::new(|_, _| false);
        let pool = WsPool::with_dialer(config(2), dialer.clone());
        pool.warmup();
        settle().await;
        assert_eq!(pool.idle_count(&(2, false, false)), 2);
        assert!(pool.get(2, false, false).is_some());
        assert_eq!(pool.idle_count(&(2, false, false)), 1);
        settle().await;
        assert_eq!(pool.idle_count(&(2, false, false)), 2);
    }

    #[tokio::test]
    async fn warmup_covers_regular_and_media_for_each_configured_dc() {
        let dialer = FakeDialer::new(|_, _| false);
        let pool = WsPool::with_dialer(config(1), dialer.clone());
        pool.warmup();
        settle().await;
        for dc in [2, 4] {
            assert_eq!(pool.idle_count(&(dc, false, false)), 1);
            assert_eq!(pool.idle_count(&(dc, true, false)), 1);
        }
    }

    #[tokio::test]
    async fn stale_connections_are_skipped() {
        let dialer = FakeDialer::new(|_, _| false);
        let pool = WsPool::with_dialer(config(1), dialer.clone());
        pool.warmup();
        settle().await;
        dialer.keep_peers.lock().clear();
        let ws = pool.get(2, false, false);
        assert!(ws.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn failed_refill_backs_off_exponentially_and_recovers() {
        let dialer = FakeDialer::new(|_, _| true);
        let pool = WsPool::with_dialer(config(1), dialer.clone());
        pool.get(2, false, false);
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let first_calls = dialer.calls.load(Ordering::SeqCst);
        assert!(first_calls >= 2);
        pool.get(2, false, false);
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert_eq!(dialer.calls.load(Ordering::SeqCst), first_calls);
        tokio::time::sleep(Duration::from_secs(2)).await;
        pool.get(2, false, false);
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(dialer.calls.load(Ordering::SeqCst) > first_calls);
    }

    #[tokio::test]
    async fn close_cancels_refill_and_closes_unclaimed_connections() {
        let mut dialer = FakeDialer::new(|_, _| false);
        Arc::get_mut(&mut dialer).unwrap().delay = Duration::from_millis(200);
        let pool = WsPool::with_dialer(config(2), dialer.clone());
        pool.get(2, false, false);
        tokio::time::sleep(Duration::from_millis(20)).await;
        pool.close().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(pool.idle_count(&(2, false, false)), 0);
        assert!(pool.state.lock().refilling.is_empty());
        assert!(pool.state.lock().rotating.is_empty());
    }

    #[tokio::test]
    async fn cf_worker_pool_keeps_one_connection_per_dc() {
        let mut cfg = ProxyConfig::default();
        cfg.cfproxy_worker_domains = vec!["w1.example.com".into(), "w2.example.com".into()];
        let dialer = FakeDialer::new(|_, _| false);
        let pool = CfWorkerPool::with_dialer(Arc::new(cfg.clone()), dialer.clone());
        assert!(pool.get(1, "149.154.175.50", &cfg.cfproxy_worker_domains).is_none());
        pool.schedule_refill(1, "149.154.175.50".into(), cfg.cfproxy_worker_domains.clone());
        settle().await;
        assert_eq!(pool.idle_count(1), 1);
        let log = dialer.log.lock();
        assert_eq!(log[0].2, "/apiws?dst=149.154.175.50&dc=1");
        drop(log);
        let (_, domain) = pool.get(1, "149.154.175.50", &cfg.cfproxy_worker_domains).unwrap();
        assert!(cfg.cfproxy_worker_domains.contains(&domain));
    }

    #[tokio::test]
    async fn cf_worker_warmup_skips_dcs_with_direct_route() {
        let mut cfg = ProxyConfig::default();
        cfg.cfproxy_worker_domains = vec!["w1.example.com".into()];
        let dialer = FakeDialer::new(|_, _| false);
        let pool = CfWorkerPool::with_dialer(Arc::new(cfg), dialer.clone());
        pool.warmup();
        settle().await;
        assert_eq!(pool.idle_count(2), 0);
        assert_eq!(pool.idle_count(4), 0);
        for dc in [1, 3, 5, 203] {
            assert_eq!(pool.idle_count(dc), 1, "dc {dc}");
        }
    }

    #[tokio::test]
    async fn cf_worker_close_cancels_refill() {
        let mut cfg = ProxyConfig::default();
        cfg.cfproxy_worker_domains = vec!["w1.example.com".into()];
        let mut dialer = FakeDialer::new(|_, _| false);
        Arc::get_mut(&mut dialer).unwrap().delay = Duration::from_millis(200);
        let pool = CfWorkerPool::with_dialer(Arc::new(cfg.clone()), dialer);
        pool.schedule_refill(1, "149.154.175.50".into(), cfg.cfproxy_worker_domains.clone());
        tokio::time::sleep(Duration::from_millis(20)).await;
        pool.close().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(pool.idle_count(1), 0);
    }

    #[test]
    fn worker_path_format() {
        assert_eq!(worker_path("1.2.3.4", 2), "/apiws?dst=1.2.3.4&dc=2");
    }
}
