use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::BoxFuture;
use h2::client::SendRequest;
use parking_lot::Mutex;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;

use crate::balancer::Balancer;
use crate::bridge::CryptoCtx;
use crate::crypto::AesCtr;
use crate::fake_tls::{ClientReader, ClientWriter};
use crate::net::{connector, server_name, tls_h2};
use crate::stats::{add, inc, stats};
use crate::utils::{PROTO_TAG_ABRIDGED, PROTO_TAG_SECURE};

pub const MAX_PACKET: usize = 4 * 1024 * 1024;
pub const MAX_PLAIN_PADDING: usize = 256;
pub const MAX_CHANNEL_REQUESTS: usize = 8;
pub const MAX_CHANNEL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_LANE_REQUESTS: usize = 64;
pub const MAX_LANE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_LANE_REPLY_BYTES: usize = 32 * 1024 * 1024;
pub const QUEUE_LIMIT: usize = 16;
pub const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
pub const CONNECTION_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct Timings {
    pub domain_cooldown: Duration,
    pub request_timeout: Duration,
    pub setup_timeout: Duration,
    pub replay_idle: Duration,
    pub replay_request: Duration,
    pub replay_check: Duration,
    pub replay_max_age: Duration,
    pub replay_slot: Duration,
    pub replay_retry: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            domain_cooldown: Duration::from_secs(30),
            request_timeout: Duration::from_secs(65),
            setup_timeout: Duration::from_secs(8),
            replay_idle: Duration::from_secs(1),
            replay_request: Duration::from_secs(3),
            replay_check: Duration::from_millis(250),
            replay_max_age: Duration::from_secs(30),
            replay_slot: Duration::from_secs(30),
            replay_retry: Duration::from_secs(2),
        }
    }
}

pub const REPLAY_HISTORY_BYTES: usize = 64 * 1024;
pub const REPLAY_HISTORY_PACKETS: usize = 16;
pub const MAX_CHANNEL_REPLAYS: usize = 2;
pub const REPLAY_MAX_ATTEMPTS: u32 = 3;

pub trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}
pub type BoxIo = Box<dyn Io>;

pub trait H2Connector: Send + Sync + 'static {
    fn connect<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<BoxIo>>;
}

pub struct TlsConnector;

impl H2Connector for TlsConnector {
    fn connect<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<BoxIo>> {
        Box::pin(async move {
            let tcp = TcpStream::connect((host, 443)).await?;
            let _ = tcp.set_nodelay(true);
            let tls = connector(tls_h2()).connect(server_name(host)?, tcp).await?;
            if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "CF origin did not negotiate h2"));
            }
            Ok(Box::new(tls) as BoxIo)
        })
    }
}

#[derive(Debug, Clone)]
pub enum ChannelError {
    Transport(i32),
    Closed,
    Other(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Transport(code) => write!(f, "MTProto transport error {code}"),
            ChannelError::Closed => write!(f, "H2 channel closed"),
            ChannelError::Other(message) => write!(f, "{message}"),
        }
    }
}

#[derive(Debug)]
pub enum PostError {
    Transport(i32, String),
    ReplyBufferFull,
    Closed,
    Http(String),
}

impl std::fmt::Display for PostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostError::Transport(code, source) => write!(f, "{code} ({source})"),
            PostError::ReplyBufferFull => write!(f, "H2 lane response buffers exceeded bound"),
            PostError::Closed => write!(f, "H2 lane closed"),
            PostError::Http(message) => write!(f, "{message}"),
        }
    }
}

impl From<PostError> for ChannelError {
    fn from(err: PostError) -> Self {
        match err {
            PostError::Transport(code, _) => ChannelError::Transport(code),
            PostError::Closed => ChannelError::Closed,
            other => ChannelError::Other(other.to_string()),
        }
    }
}

#[derive(Debug)]
pub enum PacketError {
    Eof,
    Io(io::Error),
    Invalid(String),
}

pub async fn read_packet(
    reader: &mut ClientReader,
    decryptor: &mut AesCtr,
    tag: [u8; 4],
) -> Result<(Vec<u8>, bool), PacketError> {
    async fn plaintext(
        reader: &mut ClientReader,
        decryptor: &mut AesCtr,
        count: usize,
    ) -> Result<Vec<u8>, PacketError> {
        let mut buf = vec![0u8; count];
        match reader.read_exact(&mut buf).await {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Err(PacketError::Eof),
            Err(err) => return Err(PacketError::Io(err)),
        }
        decryptor.apply(&mut buf);
        Ok(buf)
    }

    let secure = tag == PROTO_TAG_SECURE;
    let (quick, length) = if tag == PROTO_TAG_ABRIDGED {
        let first = plaintext(reader, decryptor, 1).await?[0];
        let quick = first & 0x80 != 0;
        let mut words = (first & 0x7f) as usize;
        if words == 0x7f {
            let b = plaintext(reader, decryptor, 3).await?;
            words = u32::from_le_bytes([b[0], b[1], b[2], 0]) as usize;
        }
        (quick, words * 4)
    } else {
        let b = plaintext(reader, decryptor, 4).await?;
        let value = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (value & 0x8000_0000 != 0, (value & 0x7fff_ffff) as usize)
    };
    let limit = MAX_PACKET + if secure { MAX_PLAIN_PADDING } else { 0 };
    if !(24..=limit).contains(&length) {
        return Err(PacketError::Invalid(format!("native packet length outside supported range: {length}")));
    }
    let mut body = plaintext(reader, decryptor, length).await?;
    if secure {
        let (packet_length, max_padding) = if body[..8].iter().all(|b| *b == 0) {
            (20 + u32::from_le_bytes([body[16], body[17], body[18], body[19]]) as usize, MAX_PLAIN_PADDING)
        } else {
            (24 + ((length - 24) / 16) * 16, 15)
        };
        if !(24..=length).contains(&packet_length) || length - packet_length > max_padding {
            return Err(PacketError::Invalid(format!(
                "invalid padded native packet: frame={length} packet={packet_length} limit={max_padding}"
            )));
        }
        body.truncate(packet_length);
    }
    if body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(PacketError::Invalid("invalid native packet alignment or size".to_string()));
    }
    Ok((body, quick))
}

pub fn encode_reply(body: &[u8], tag: [u8; 4]) -> Result<Vec<u8>, String> {
    if body.is_empty() || body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(format!("invalid HTTP MTProto response length: {}", body.len()));
    }
    if tag == PROTO_TAG_ABRIDGED {
        let words = body.len() / 4;
        let mut out = if words < 0x7f {
            vec![words as u8]
        } else {
            let mut v = vec![0x7f];
            v.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
            v
        };
        out.extend_from_slice(body);
        return Ok(out);
    }
    let padding_len = if tag == PROTO_TAG_SECURE { rand::thread_rng().gen_range(0..4usize) } else { 0 };
    let mut out = ((body.len() + padding_len) as u32).to_le_bytes().to_vec();
    out.extend_from_slice(body);
    let mut padding = vec![0u8; padding_len];
    rand::thread_rng().fill(&mut padding[..]);
    out.extend_from_slice(&padding);
    Ok(out)
}

struct Pending {
    len: usize,
    abort: AbortHandle,
}

struct ReplayPacket {
    sent_at: Instant,
    body: Arc<Vec<u8>>,
    sequence: u64,
    attempts: u32,
    last_attempt_at: Option<Instant>,
    pending: Option<u64>,
    originals: HashSet<u64>,
    retired: bool,
    reply_id: Option<Vec<u8>>,
}

impl ReplayPacket {
    fn replayed(&self) -> bool {
        self.last_attempt_at.is_some() || self.attempts > 0
    }
}

struct UploadWait {
    phase: &'static str,
    bytes: usize,
}

struct ChState {
    closed: bool,
    transport_error: Option<i32>,
    pending: BTreeMap<u64, Pending>,
    pending_bytes: usize,
    reply_bytes: usize,
    queue: VecDeque<Result<Vec<u8>, ChannelError>>,
    sent_since: HashMap<u64, Instant>,
    receiving: HashSet<u64>,
    replay_pending: HashSet<u64>,
    replay_history: Vec<ReplayPacket>,
    replay_key: Option<Vec<u8>>,
    requests: u64,
    replay_requests: u64,
    up: u64,
    down: u64,
    quick_requests: u64,
    replay_rotations: u64,
    capacity_rotations: u64,
    last_progress: Instant,
    last_native_send: Instant,
    delivering_since: Option<Instant>,
    upload_wait: Option<UploadWait>,
    next_request_id: u64,
}

impl ChState {
    fn native_backpressure(&self) -> bool {
        self.reply_bytes > 0 || self.delivering_since.is_some()
    }

    fn has_capacity(&self, length: usize) -> bool {
        self.pending.len() < MAX_CHANNEL_REQUESTS && self.pending_bytes + length <= MAX_CHANNEL_BYTES
    }

    fn replay_limit(&self, entry: &ReplayPacket) -> u32 {
        let is_last = self.replay_history.last().map(|last| last.sequence == entry.sequence).unwrap_or(false);
        if !entry.originals.is_empty() || entry.retired || is_last {
            REPLAY_MAX_ATTEMPTS
        } else {
            0
        }
    }

    fn overdue_original(&self, entry: &ReplayPacket, now: Instant, timings: &Timings) -> bool {
        entry.retired
            || entry.originals.iter().any(|task| {
                self.sent_since
                    .get(task)
                    .map(|sent| !self.receiving.contains(task) && now.duration_since(*sent) >= timings.replay_request)
                    .unwrap_or(false)
            })
    }

    fn replay_blocker(&self, entry: &ReplayPacket, now: Instant, timings: &Timings) -> Option<&'static str> {
        if now < entry.sent_at || now.duration_since(entry.sent_at) > timings.replay_max_age {
            return Some("expired");
        }
        if entry.attempts >= self.replay_limit(entry) {
            return Some("budget-used");
        }
        if self.native_backpressure() {
            return Some("native-backpressure");
        }
        if entry.originals.iter().any(|t| self.receiving.contains(t)) {
            return Some("original-body");
        }
        if entry.pending.map(|t| self.receiving.contains(&t)).unwrap_or(false) {
            return Some("replay-body");
        }
        if entry.replayed() {
            if let Some(last) = entry.last_attempt_at {
                if now.duration_since(last) < timings.replay_retry {
                    return Some("backoff-or-progress");
                }
            }
        }
        if self.overdue_original(entry, now, timings) {
            return None;
        }
        let is_last = self.replay_history.last().map(|last| last.sequence == entry.sequence).unwrap_or(false);
        if !is_last || self.pending.keys().any(|task| Some(*task) != entry.pending) {
            return Some("receiver-active");
        }
        if entry.replayed() && now.duration_since(self.last_progress) < timings.replay_idle {
            return Some("backoff-or-progress");
        }
        None
    }

    fn capacity_candidate(&self, now: Instant, timings: &Timings) -> Option<(u64, Option<u64>)> {
        let mut items: Vec<(u64, Instant)> = self.sent_since.iter().map(|(t, s)| (*t, *s)).collect();
        items.sort_by_key(|(task, sent)| (!self.replay_pending.contains(task), *sent));
        for (task, sent) in items {
            if !self.pending.contains_key(&task)
                || self.receiving.contains(&task)
                || now.duration_since(sent) < timings.replay_request
            {
                continue;
            }
            if self.replay_pending.contains(&task) {
                return Some((task, None));
            }
            if let Some(entry) = self.replay_history.iter().find(|e| e.originals.contains(&task)) {
                if now.duration_since(entry.sent_at) <= timings.replay_max_age {
                    return Some((task, Some(entry.sequence)));
                }
            }
        }
        None
    }

    fn trim_history(&mut self, now: Instant, timings: &Timings) {
        let mut retained: usize = self.replay_history.iter().map(|e| e.body.len()).sum();
        while self.replay_history.len() > REPLAY_HISTORY_PACKETS || retained > REPLAY_HISTORY_BYTES {
            let index = self
                .replay_history
                .iter()
                .position(|e| {
                    e.originals.is_empty()
                        && !(e.retired
                            && e.attempts < REPLAY_MAX_ATTEMPTS
                            && now.duration_since(e.sent_at) <= timings.replay_max_age)
                })
                .unwrap_or(0);
            let victim = self.replay_history.remove(index);
            retained -= victim.body.len();
        }
    }

    fn remember_packet(&mut self, body: &Arc<Vec<u8>>, now: Instant) -> Option<u64> {
        let key = body[..8.min(body.len())].to_vec();
        if key.iter().all(|b| *b == 0) {
            return None;
        }
        if self.replay_key.as_deref() != Some(&key[..]) {
            self.replay_history.clear();
            self.replay_key = Some(key);
        }
        if body.len() > REPLAY_HISTORY_BYTES {
            return None;
        }
        if let Some(existing) = self.replay_history.iter().find(|e| *e.body == **body) {
            return Some(existing.sequence);
        }
        let sequence = self.requests;
        self.replay_history.push(ReplayPacket {
            sent_at: now,
            body: body.clone(),
            sequence,
            attempts: 0,
            last_attempt_at: None,
            pending: None,
            originals: HashSet::new(),
            retired: false,
            reply_id: None,
        });
        Some(sequence)
    }

    fn packet_mut(&mut self, sequence: u64) -> Option<&mut ReplayPacket> {
        self.replay_history.iter_mut().find(|e| e.sequence == sequence)
    }
}

pub struct HttpChannel {
    lane: Arc<HttpLane>,
    pub channel_id: u64,
    pub label: String,
    st: Mutex<ChState>,
    queue_notify: Notify,
    capacity_notify: Notify,
    recovery_notify: Notify,
    send_lock: tokio::sync::Mutex<()>,
    close_lock: tokio::sync::Mutex<bool>,
    timings: Timings,
}

struct RequestGuard {
    channel: Arc<HttpChannel>,
    id: u64,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.channel.finish_request(self.id);
    }
}

impl HttpChannel {
    fn new(lane: Arc<HttpLane>, channel_id: u64, label: String) -> Arc<Self> {
        let now = Instant::now();
        let timings = lane.timings;
        let channel = Arc::new(Self {
            lane: lane.clone(),
            channel_id,
            label,
            st: Mutex::new(ChState {
                closed: false,
                transport_error: None,
                pending: BTreeMap::new(),
                pending_bytes: 0,
                reply_bytes: 0,
                queue: VecDeque::new(),
                sent_since: HashMap::new(),
                receiving: HashSet::new(),
                replay_pending: HashSet::new(),
                replay_history: Vec::new(),
                replay_key: None,
                requests: 0,
                replay_requests: 0,
                up: 0,
                down: 0,
                quick_requests: 0,
                replay_rotations: 0,
                capacity_rotations: 0,
                last_progress: now,
                last_native_send: now,
                delivering_since: None,
                upload_wait: None,
                next_request_id: 0,
            }),
            queue_notify: Notify::new(),
            capacity_notify: Notify::new(),
            recovery_notify: Notify::new(),
            send_lock: tokio::sync::Mutex::new(()),
            close_lock: tokio::sync::Mutex::new(false),
            timings,
        });
        lane.channels.lock().push(channel.clone());
        channel
    }

    pub fn is_closed(&self) -> bool {
        self.st.lock().closed
    }

    pub fn transport_error(&self) -> Option<i32> {
        self.st.lock().transport_error
    }

    pub fn bytes_down(&self) -> u64 {
        self.st.lock().down
    }

    pub fn pending_len(&self) -> usize {
        self.st.lock().pending.len()
    }

    pub fn replay_requests(&self) -> u64 {
        self.st.lock().replay_requests
    }

    pub fn requests(&self) -> u64 {
        self.st.lock().requests
    }

    fn wake_receiver(&self) {
        let st = self.st.lock();
        if !st.closed && st.pending.is_empty() && !st.native_backpressure() {
            self.recovery_notify.notify_one();
        }
    }

    fn fail(&self, error: ChannelError) {
        let mut st = self.st.lock();
        if st.closed {
            return;
        }
        if let ChannelError::Transport(code) = &error {
            st.transport_error = Some(*code);
        }
        st.closed = true;
        st.queue.clear();
        st.reply_bytes = 0;
        st.queue.push_back(Err(error));
        drop(st);
        self.recovery_notify.notify_one();
        self.queue_notify.notify_one();
        self.capacity_notify.notify_waiters();
    }

    pub async fn receive(&self) -> Result<Vec<u8>, ChannelError> {
        loop {
            let notified = self.queue_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.st.lock();
                if let Some(item) = st.queue.pop_front() {
                    match item {
                        Ok(value) => {
                            st.reply_bytes -= value.len();
                            drop(st);
                            self.wake_receiver();
                            return Ok(value);
                        }
                        Err(error) => {
                            st.queue.push_front(Err(error.clone()));
                            return Err(error);
                        }
                    }
                }
            }
            notified.await;
        }
    }

    pub fn mark_delivering(&self, active: bool) {
        let mut st = self.st.lock();
        st.delivering_since = if active { Some(Instant::now()) } else { None };
    }

    pub fn delivered(&self, len: usize) {
        {
            let mut st = self.st.lock();
            st.down += len as u64;
            st.last_progress = Instant::now();
        }
        add(&stats().bytes_down, len as u64);
        self.wake_receiver();
    }

    pub async fn send(self: &Arc<Self>, body: Vec<u8>, quick: bool, replay: bool) -> Result<bool, ChannelError> {
        let _guard = if replay {
            match self.send_lock.try_lock() {
                Ok(guard) => guard,
                Err(_) => return Ok(false),
            }
        } else {
            self.st.lock().upload_wait =
                Some(UploadWait { phase: "send-lock", bytes: body.len() });
            self.send_lock.lock().await
        };
        let result = self.send_inner(Arc::new(body), quick, replay).await;
        if !replay {
            self.st.lock().upload_wait = None;
        }
        result
    }

    async fn wait_channel_capacity(&self, length: usize) -> Result<(), ChannelError> {
        let wait = async {
            loop {
                let notified = self.capacity_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let st = self.st.lock();
                    if st.closed || st.has_capacity(length) {
                        return;
                    }
                }
                notified.await;
            }
        };
        tokio::time::timeout(self.timings.request_timeout, wait)
            .await
            .map_err(|_| ChannelError::Other("timed out waiting for channel capacity".to_string()))
    }

    async fn send_inner(self: &Arc<Self>, body: Arc<Vec<u8>>, quick: bool, replay: bool) -> Result<bool, ChannelError> {
        let length = body.len();
        if replay {
            if !self.st.lock().has_capacity(length) {
                return Ok(false);
            }
        } else {
            if let Some(w) = self.st.lock().upload_wait.as_mut() {
                w.phase = "channel-capacity";
            }
            self.wait_channel_capacity(length).await?;
        }
        if self.st.lock().closed {
            return Err(ChannelError::Closed);
        }
        if !replay {
            if let Some(w) = self.st.lock().upload_wait.as_mut() {
                w.phase = "lane-capacity";
            }
        }
        if !self.lane.reserve(length, !replay).await.map_err(ChannelError::from)? {
            return Ok(false);
        }
        let now = Instant::now();
        let mut st = self.st.lock();
        if st.closed {
            drop(st);
            self.lane.release(length);
            return Err(ChannelError::Closed);
        }
        let replay_sequence = if replay {
            st.replay_history.iter().find(|e| *e.body == *body).map(|e| e.sequence)
        } else {
            None
        };
        if replay {
            let due = match replay_sequence {
                Some(seq) => {
                    let entry = st.replay_history.iter().find(|e| e.sequence == seq).expect("entry");
                    entry.pending.is_none() && st.replay_blocker(entry, now, &self.timings).is_none()
                }
                None => false,
            };
            if !due {
                drop(st);
                self.lane.release(length);
                return Ok(false);
            }
        }
        st.pending_bytes += length;
        st.requests += 1;
        st.replay_requests += replay as u64;
        st.up += length as u64;
        add(&stats().bytes_up, length as u64);
        if !replay {
            st.last_native_send = now;
        }
        let native_sequence = if !replay { st.remember_packet(&body, now) } else { None };
        if quick {
            st.quick_requests += 1;
        }
        let packet_sequence = replay_sequence.or(native_sequence);
        st.next_request_id += 1;
        let id = st.next_request_id;
        let channel = self.clone();
        let task_body = body.clone();
        let handle = tokio::spawn(async move {
            channel.run_request(id, task_body, replay, packet_sequence).await;
        });
        st.pending.insert(id, Pending { len: length, abort: handle.abort_handle() });
        if let Some(seq) = native_sequence {
            if let Some(entry) = st.packet_mut(seq) {
                entry.originals.insert(id);
            }
            st.trim_history(now, &self.timings);
        }
        if replay {
            let seq = replay_sequence.expect("replay sequence");
            st.replay_pending.insert(id);
            if let Some(entry) = st.packet_mut(seq) {
                entry.attempts += 1;
                entry.last_attempt_at = Some(now);
                entry.pending = Some(id);
            }
        }
        Ok(true)
    }

    async fn run_request(self: Arc<Self>, id: u64, body: Arc<Vec<u8>>, replay: bool, packet: Option<u64>) {
        let _guard = RequestGuard { channel: self.clone(), id };
        let result = self.lane.post(&body, Some((&self, id)), replay).await;
        let now = Instant::now();
        match result {
            Ok(reply) => {
                self.st.lock().last_progress = now;
                if reply.is_empty() {
                    return;
                }
                let mut st = self.st.lock();
                if st.closed {
                    return;
                }
                if let Some(seq) = packet {
                    let reply_id = reply[..24.min(reply.len())].to_vec();
                    if let Some(entry) = st.packet_mut(seq) {
                        if entry.reply_id.as_deref() != Some(&reply_id[..]) {
                            entry.reply_id = Some(reply_id);
                            entry.attempts = 0;
                        }
                    }
                }
                if st.queue.len() >= QUEUE_LIMIT || st.reply_bytes + reply.len() > MAX_CHANNEL_BYTES {
                    drop(st);
                    inc(&stats().h2_errors);
                    log::warn!(
                        "[{}] H2 lane={} channel={} request failed: BufferError: H2 client response queue exceeded bound; \
                         closing native channel, reconnect may select another domain",
                        self.label, self.lane.lane_id, self.channel_id
                    );
                    self.fail(ChannelError::Other("H2 client response queue exceeded bound".to_string()));
                    return;
                }
                st.reply_bytes += reply.len();
                st.queue.push_back(Ok(reply));
                drop(st);
                self.queue_notify.notify_one();
            }
            Err(PostError::Transport(code, source)) => {
                inc(&stats().h2_errors);
                if !self.is_closed() {
                    log::warn!(
                        "[{}] H2 lane={} channel={} host={} MTProto transport error={code} ({source}) \
                         bytes={} replay={}; reporting to client",
                        self.label, self.lane.lane_id, self.channel_id, self.lane.host, body.len(), replay as u8
                    );
                }
                self.fail(ChannelError::Transport(code));
            }
            Err(PostError::Closed) => self.fail(ChannelError::Closed),
            Err(err) => {
                inc(&stats().h2_errors);
                log::warn!(
                    "[{}] H2 lane={} channel={} request failed: {err}; \
                     closing native channel, reconnect may select another domain",
                    self.label, self.lane.lane_id, self.channel_id
                );
                self.fail(ChannelError::Other(err.to_string()));
            }
        }
    }

    fn finish_request(&self, id: u64) {
        let length = {
            let mut st = self.st.lock();
            let Some(pending) = st.pending.remove(&id) else { return };
            st.pending_bytes -= pending.len;
            st.sent_since.remove(&id);
            st.replay_pending.remove(&id);
            st.receiving.remove(&id);
            for entry in st.replay_history.iter_mut() {
                entry.originals.remove(&id);
                if entry.pending == Some(id) {
                    entry.pending = None;
                }
            }
            pending.len
        };
        self.lane.release(length);
        self.capacity_notify.notify_waiters();
        self.wake_receiver();
    }

    fn cancel_request(&self, id: u64) {
        let abort = self.st.lock().pending.get(&id).map(|p| p.abort.clone());
        if let Some(abort) = abort {
            abort.abort();
        }
        self.finish_request(id);
    }

    pub(crate) fn mark_sent(&self, id: u64) {
        self.st.lock().sent_since.insert(id, Instant::now());
    }

    pub(crate) fn mark_receiving(&self, id: u64) {
        let mut st = self.st.lock();
        if st.pending.contains_key(&id) {
            st.receiving.insert(id);
            st.last_progress = Instant::now();
        }
    }

    pub(crate) fn unmark_receiving(&self, id: u64) {
        self.st.lock().receiving.remove(&id);
    }

    pub(crate) fn touch_progress(&self) {
        self.st.lock().last_progress = Instant::now();
    }

    async fn make_upload_room(&self, now: Instant) {
        let (phase, bytes) = {
            let st = self.st.lock();
            if st.closed {
                return;
            }
            match &st.upload_wait {
                Some(w) => (w.phase, w.bytes),
                None => return,
            }
        };
        let channels: Vec<Arc<HttpChannel>> = match phase {
            "channel-capacity" => {
                if self.st.lock().has_capacity(bytes) {
                    return;
                }
                let me = self.lane.channels.lock().iter().find(|c| c.channel_id == self.channel_id).cloned();
                me.into_iter().collect()
            }
            "lane-capacity" => {
                if self.lane.has_capacity(bytes) {
                    return;
                }
                let mut all: Vec<Arc<HttpChannel>> = self.lane.channels.lock().clone();
                all.sort_by_key(|c| c.st.lock().sent_since.values().min().copied().unwrap_or(now));
                all
            }
            _ => return,
        };
        for channel in channels {
            let candidate = channel.st.lock().capacity_candidate(now, &self.timings);
            let Some((task, sequence)) = candidate else { continue };
            {
                let mut st = channel.st.lock();
                st.sent_since.remove(&task);
                if let Some(seq) = sequence {
                    if let Some(entry) = st.packet_mut(seq) {
                        entry.retired = true;
                    }
                }
                st.capacity_rotations += 1;
            }
            log::debug!(
                "H2 CAPACITY lane={} waiting_channel={} release_channel={} reason={phase}",
                self.lane.lane_id, self.channel_id, channel.channel_id
            );
            channel.cancel_request(task);
            self.lane.capacity_rotations.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    pub async fn recover(self: &Arc<Self>) {
        loop {
            if self.is_closed() {
                return;
            }
            let _ = tokio::time::timeout(self.timings.replay_check, self.recovery_notify.notified()).await;
            let now = Instant::now();
            self.make_upload_room(now).await;
            let plan = {
                let st = self.st.lock();
                if st.closed {
                    return;
                }
                if st.native_backpressure() {
                    continue;
                }
                let mut candidates: Vec<(bool, i64, u64)> = st
                    .replay_history
                    .iter()
                    .map(|e| {
                        let overdue = st.overdue_original(e, now, &self.timings);
                        let order = if overdue { e.sequence as i64 } else { -(e.sequence as i64) };
                        (!overdue, order, e.sequence)
                    })
                    .collect();
                candidates.sort();
                let mut chosen = None;
                for (_, _, sequence) in candidates {
                    let entry = st.replay_history.iter().find(|e| e.sequence == sequence).expect("entry");
                    if st.replay_blocker(entry, now, &self.timings).is_some() {
                        continue;
                    }
                    let mut replace = entry.pending;
                    if replace.is_none() && st.replay_pending.len() >= MAX_CHANNEL_REPLAYS {
                        replace = st
                            .pending
                            .keys()
                            .find(|t| st.replay_pending.contains(t) && !st.receiving.contains(t))
                            .copied();
                        if replace.is_none() {
                            continue;
                        }
                    }
                    if let Some(task) = replace {
                        let sent = st.sent_since.get(&task);
                        let blocked = st.receiving.contains(&task)
                            || sent.map(|s| now.duration_since(*s) < self.timings.replay_slot).unwrap_or(true);
                        if blocked {
                            continue;
                        }
                    }
                    chosen = Some((entry.body.clone(), replace));
                    break;
                }
                chosen
            };
            let Some((body, replace)) = plan else { continue };
            if let Some(task) = replace {
                self.cancel_request(task);
                self.st.lock().replay_rotations += 1;
            }
            let _ = self.send((*body).clone(), false, true).await;
        }
    }

    pub async fn close(self: &Arc<Self>) {
        let mut done = self.close_lock.lock().await;
        if *done {
            return;
        }
        self.fail(ChannelError::Closed);
        let ids: Vec<u64> = self.st.lock().pending.keys().copied().collect();
        for id in ids {
            self.cancel_request(id);
        }
        {
            let mut st = self.st.lock();
            st.closed = true;
            st.replay_pending.clear();
            st.replay_history.clear();
            st.sent_since.clear();
        }
        self.lane.channels.lock().retain(|c| c.channel_id != self.channel_id);
        *done = true;
        let st = self.st.lock();
        log::debug!(
            "[{}] H2 channel={} closed lane={} requests={} replays={} rotations={} capacity_rotations={} up={} down={} \
             quickack={} remaining_channels={}",
            self.label, self.channel_id, self.lane.lane_id, st.requests, st.replay_requests, st.replay_rotations,
            st.capacity_rotations, st.up, st.down, st.quick_requests, self.lane.channels.lock().len()
        );
    }
}

struct Conn {
    send: SendRequest<Bytes>,
    dead: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    driver: JoinHandle<()>,
}

struct LaneCap {
    inflight: usize,
    queued_bytes: usize,
    max_inflight: usize,
}

pub struct HttpLane {
    pub host: String,
    pub lane_id: u64,
    connector: Arc<dyn H2Connector>,
    timings: Timings,
    conn: tokio::sync::Mutex<Option<Conn>>,
    channels: Mutex<Vec<Arc<HttpChannel>>>,
    failed_until: Mutex<Option<Instant>>,
    closed: AtomicBool,
    cap: Mutex<LaneCap>,
    cap_notify: Notify,
    reply_buffer_bytes: AtomicUsize,
    pub tcp_connections: AtomicU64,
    pub requests: AtomicU64,
    pub responses: AtomicU64,
    pub errors: AtomicU64,
    pub replays: AtomicU64,
    pub capacity_rotations: AtomicU64,
    next_channel: AtomicU64,
}

fn http_err(err: impl std::fmt::Display) -> PostError {
    PostError::Http(err.to_string())
}

impl HttpLane {
    pub fn new(host: String, lane_id: u64, connector: Arc<dyn H2Connector>, timings: Timings) -> Arc<Self> {
        Arc::new(Self {
            host,
            lane_id,
            connector,
            timings,
            conn: tokio::sync::Mutex::new(None),
            channels: Mutex::new(Vec::new()),
            failed_until: Mutex::new(None),
            closed: AtomicBool::new(false),
            cap: Mutex::new(LaneCap { inflight: 0, queued_bytes: 0, max_inflight: 0 }),
            cap_notify: Notify::new(),
            reply_buffer_bytes: AtomicUsize::new(0),
            tcp_connections: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            responses: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            replays: AtomicU64::new(0),
            capacity_rotations: AtomicU64::new(0),
            next_channel: AtomicU64::new(0),
        })
    }

    pub fn channel_count(&self) -> usize {
        self.channels.lock().len()
    }

    pub fn failed_until(&self) -> Option<Instant> {
        *self.failed_until.lock()
    }

    pub fn reply_buffer_bytes(&self) -> usize {
        self.reply_buffer_bytes.load(Ordering::Relaxed)
    }

    async fn connection(&self) -> Result<(SendRequest<Bytes>, Arc<AtomicBool>, Arc<AtomicUsize>), PostError> {
        let mut guard = self.conn.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(PostError::Closed);
        }
        if let Some(conn) = guard.as_ref() {
            if !conn.dead.load(Ordering::Acquire) {
                return Ok((conn.send.clone(), conn.dead.clone(), conn.active.clone()));
            }
        }
        if let Some(old) = guard.take() {
            old.driver.abort();
        }
        self.tcp_connections.fetch_add(1, Ordering::Relaxed);
        inc(&stats().h2_tcp_connections);
        log::debug!("H2 lane={} TCP_OPEN connection={} host={}", self.lane_id, self.tcp_connections.load(Ordering::Relaxed), self.host);
        let io = tokio::time::timeout(Duration::from_secs(8), self.connector.connect(&self.host))
            .await
            .map_err(|_| PostError::Http("H2 TLS connect timed out".to_string()))?
            .map_err(http_err)?;
        let (send, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_RECEIVE_WINDOW)
            .initial_connection_window_size(CONNECTION_RECEIVE_WINDOW)
            .enable_push(false)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(http_err)?;
        let dead = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let dead_flag = dead.clone();
        let driver = tokio::spawn(async move {
            if let Err(err) = connection.await {
                log::debug!("H2 connection ended: {err}");
            }
            dead_flag.store(true, Ordering::Release);
        });
        *guard = Some(Conn { send: send.clone(), dead: dead.clone(), active: active.clone(), driver });
        Ok((send, dead, active))
    }

    pub async fn preflight(&self) -> Result<(), PostError> {
        let started = Instant::now();
        let (send, _dead, _active) = self.connection().await?;
        let mut send = send.ready().await.map_err(http_err)?;
        let request = http::Request::builder()
            .method("HEAD")
            .uri(format!("https://{}/api", self.host))
            .body(())
            .map_err(http_err)?;
        let (response, _stream) = send.send_request(request, true).map_err(http_err)?;
        let response = tokio::time::timeout(self.timings.request_timeout, response)
            .await
            .map_err(|_| PostError::Http("preflight timed out".to_string()))?
            .map_err(http_err)?;
        if response.version() != http::Version::HTTP_2 {
            return Err(PostError::Http(format!("CF /api preflight negotiated {:?}", response.version())));
        }
        let status = response.status().as_u16();
        if !((200..300).contains(&status) || status == 405 || status == 501) {
            let ray = response.headers().get("cf-ray").and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
            return Err(PostError::Http(format!("CF /api preflight HTTP {status} cf_ray={ray}")));
        }
        log::debug!(
            "H2 lane={} ready host={} status={status} ms={:.0}",
            self.lane_id, self.host, started.elapsed().as_secs_f64() * 1000.0
        );
        Ok(())
    }

    fn has_capacity(&self, length: usize) -> bool {
        let cap = self.cap.lock();
        cap.inflight < MAX_LANE_REQUESTS && cap.queued_bytes + length <= MAX_LANE_BYTES
    }

    async fn reserve(&self, length: usize, wait: bool) -> Result<bool, PostError> {
        if !wait {
            if !self.has_capacity(length) {
                return Ok(false);
            }
        } else {
            let waiter = async {
                loop {
                    let notified = self.cap_notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if self.closed.load(Ordering::Acquire) || self.has_capacity(length) {
                        return;
                    }
                    notified.await;
                }
            };
            tokio::time::timeout(self.timings.request_timeout, waiter)
                .await
                .map_err(|_| PostError::Http("timed out waiting for lane capacity".to_string()))?;
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(PostError::Closed);
        }
        let mut cap = self.cap.lock();
        cap.inflight += 1;
        cap.queued_bytes += length;
        cap.max_inflight = cap.max_inflight.max(cap.inflight);
        Ok(true)
    }

    fn release(&self, length: usize) {
        {
            let mut cap = self.cap.lock();
            cap.inflight = cap.inflight.saturating_sub(1);
            cap.queued_bytes = cap.queued_bytes.saturating_sub(length);
        }
        self.cap_notify.notify_waiters();
    }

    pub fn inflight(&self) -> (usize, usize) {
        let cap = self.cap.lock();
        (cap.inflight, cap.max_inflight)
    }

    pub async fn post(
        &self,
        body: &[u8],
        channel: Option<(&Arc<HttpChannel>, u64)>,
        replay: bool,
    ) -> Result<Vec<u8>, PostError> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.replays.fetch_add(replay as u64, Ordering::Relaxed);
        inc(&stats().h2_requests);
        let mut buffered = 0usize;
        let result = self.post_inner(body, channel, &mut buffered).await;
        self.reply_buffer_bytes.fetch_sub(buffered, Ordering::Relaxed);
        if let Some((channel, id)) = channel {
            channel.unmark_receiving(id);
        }
        match &result {
            Err(PostError::Transport(..)) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
            Err(PostError::ReplyBufferFull) | Err(PostError::Closed) => {}
            Err(_) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                *self.failed_until.lock() = Some(Instant::now() + self.timings.domain_cooldown);
            }
            Ok(_) => {}
        }
        result
    }

    async fn post_inner(
        &self,
        body: &[u8],
        channel: Option<(&Arc<HttpChannel>, u64)>,
        buffered: &mut usize,
    ) -> Result<Vec<u8>, PostError> {
        let timeout = self.timings.request_timeout;
        let (send, dead, active) = self.connection().await?;
        struct ActiveGuard(Arc<AtomicUsize>);
        impl Drop for ActiveGuard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        active.fetch_add(1, Ordering::AcqRel);
        let _active = ActiveGuard(active.clone());

        let mut send = tokio::time::timeout(timeout, send.ready())
            .await
            .map_err(|_| PostError::Http("H2 stream capacity exhausted".to_string()))?
            .map_err(http_err)?;
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{}/api", self.host))
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .header("content-length", body.len().to_string())
            .body(())
            .map_err(http_err)?;
        let (response, mut stream) = send.send_request(request, false).map_err(http_err)?;

        let upload = async {
            let mut offset = 0usize;
            while offset < body.len() {
                stream.reserve_capacity(body.len() - offset);
                let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
                    .await
                    .ok_or_else(|| PostError::Http("H2 stream closed during upload".to_string()))?
                    .map_err(http_err)?;
                if capacity == 0 {
                    continue;
                }
                let end = (offset + capacity).min(body.len());
                stream
                    .send_data(Bytes::copy_from_slice(&body[offset..end]), false)
                    .map_err(http_err)?;
                offset = end;
            }
            stream.send_data(Bytes::new(), true).map_err(http_err)?;
            Ok::<(), PostError>(())
        };
        tokio::time::timeout(timeout, upload)
            .await
            .map_err(|_| PostError::Http("H2 upload timed out".to_string()))??;
        if let Some((channel, id)) = channel {
            channel.mark_sent(id);
        }

        let timed_out = |dead: &Arc<AtomicBool>, active: &Arc<AtomicUsize>| {
            if active.load(Ordering::Acquire) <= 1 {
                dead.store(true, Ordering::Release);
            }
            PostError::Http("Timed out waiting for H2 stream".to_string())
        };

        let response = match tokio::time::timeout(timeout, response).await {
            Ok(result) => result.map_err(http_err)?,
            Err(_) => return Err(timed_out(&dead, &active)),
        };
        if let Some((channel, id)) = channel {
            channel.mark_receiving(id);
        }
        let status = response.status().as_u16();
        let ray = response.headers().get("cf-ray").and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
        if response.version() != http::Version::HTTP_2 {
            return Err(PostError::Http(format!("CF /api downgraded to {:?}", response.version())));
        }
        if matches!(status, 403 | 404 | 429 | 444) {
            return Err(PostError::Transport(-(status as i32), format!("HTTP {status} cf_ray={ray}")));
        }
        if status != 200 {
            return Err(PostError::Http(format!("CF /api HTTP {status} cf_ray={ray}")));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if content_type.contains("text/html") {
            return Err(PostError::Http("CF /api returned HTML instead of MTProto".to_string()));
        }
        let declared: Option<usize> = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        if let Some(declared) = declared {
            if declared > MAX_PACKET {
                return Err(PostError::Http("H2 response Content-Length exceeds native packet bound".to_string()));
            }
        }
        let mut recv = response.into_body();
        let mut content: Vec<u8> = Vec::new();
        loop {
            let chunk = match tokio::time::timeout(timeout, recv.data()).await {
                Ok(Some(result)) => result.map_err(http_err)?,
                Ok(None) => break,
                Err(_) => return Err(timed_out(&dead, &active)),
            };
            let len = chunk.len();
            if content.len() + len > MAX_PACKET {
                return Err(PostError::Http("H2 response exceeds native packet bound".to_string()));
            }
            if self.reply_buffer_bytes.load(Ordering::Relaxed) + len > MAX_LANE_REPLY_BYTES {
                return Err(PostError::ReplyBufferFull);
            }
            self.reply_buffer_bytes.fetch_add(len, Ordering::Relaxed);
            *buffered += len;
            content.extend_from_slice(&chunk);
            let _ = recv.flow_control().release_capacity(len);
            if let Some((channel, _)) = channel {
                channel.touch_progress();
            }
        }
        if let Some(declared) = declared {
            if content.len() != declared {
                return Err(PostError::Http("incomplete H2 response body".to_string()));
            }
        }
        if !content.is_empty() && content.len() % 4 != 0 {
            return Err(PostError::Http("CF /api response is not an aligned MTProto packet".to_string()));
        }
        if content.len() == 4 {
            let code = i32::from_le_bytes([content[0], content[1], content[2], content[3]]);
            if code < 0 {
                return Err(PostError::Transport(code, "HTTP 200 payload".to_string()));
            }
        }
        self.responses.fetch_add(1, Ordering::Relaxed);
        Ok(content)
    }

    pub fn open_channel(self: &Arc<Self>, label: &str) -> Arc<HttpChannel> {
        let id = self.next_channel.fetch_add(1, Ordering::Relaxed) + 1;
        HttpChannel::new(self.clone(), id, label.to_string())
    }

    pub async fn close(self: &Arc<Self>) {
        self.closed.store(true, Ordering::Release);
        self.cap_notify.notify_waiters();
        let channels: Vec<Arc<HttpChannel>> = self.channels.lock().clone();
        for channel in channels {
            channel.close().await;
        }
        if let Some(conn) = self.conn.lock().await.take() {
            conn.driver.abort();
        }
        log::debug!(
            "H2 CLOSED lane={} host={} tcp_connections={} requests={} replies={} errors={} replays={}",
            self.lane_id, self.host, self.tcp_connections.load(Ordering::Relaxed),
            self.requests.load(Ordering::Relaxed), self.responses.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed), self.replays.load(Ordering::Relaxed)
        );
    }
}

pub struct CfH2Pool {
    balancer: Arc<Balancer>,
    connector: Arc<dyn H2Connector>,
    timings: Timings,
    lanes: Mutex<HashMap<String, Arc<HttpLane>>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    failed_until: Mutex<HashMap<String, Instant>>,
    setup_retry_after: Mutex<HashMap<i32, Instant>>,
    next_lane: AtomicU64,
    closed: AtomicBool,
}

impl CfH2Pool {
    pub fn new(balancer: Arc<Balancer>) -> Arc<Self> {
        Self::with_connector(balancer, Arc::new(TlsConnector), Timings::default())
    }

    pub fn with_connector(balancer: Arc<Balancer>, connector: Arc<dyn H2Connector>, timings: Timings) -> Arc<Self> {
        Arc::new(Self {
            balancer,
            connector,
            timings,
            lanes: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            failed_until: Mutex::new(HashMap::new()),
            setup_retry_after: Mutex::new(HashMap::new()),
            next_lane: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        })
    }

    pub fn lane_count(&self) -> usize {
        self.lanes.lock().len()
    }

    pub fn lane(&self, host: &str) -> Option<Arc<HttpLane>> {
        self.lanes.lock().get(host).cloned()
    }

    pub async fn open(self: &Arc<Self>, dc: i32, label: &str) -> Option<Arc<HttpChannel>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        if let Some(after) = self.setup_retry_after.lock().get(&dc) {
            if Instant::now() < *after {
                return None;
            }
        }
        match tokio::time::timeout(self.timings.setup_timeout, self.open_inner(dc, label)).await {
            Ok(channel) => channel,
            Err(_) => {
                self.setup_retry_after.lock().insert(dc, Instant::now() + self.timings.domain_cooldown);
                inc(&stats().h2_errors);
                log::warn!(
                    "[{label}] H2 DC{dc} setup timed out; using WS for {:.0}s",
                    self.timings.domain_cooldown.as_secs_f64()
                );
                None
            }
        }
    }

    async fn open_inner(self: &Arc<Self>, dc: i32, label: &str) -> Option<Arc<HttpChannel>> {
        if crate::utils::dc_default_ip(dc).is_none() {
            log::warn!("[{label}] H2 unsupported DC{dc} -> existing WS route");
            return None;
        }
        for base_domain in self.balancer.get_domains_for_dc(dc) {
            let host = format!("kws{dc}.{base_domain}");
            let lock = self.locks.lock().entry(host.clone()).or_default().clone();
            let _held = lock.lock().await;
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            let existing = self.lanes.lock().get(&host).cloned();
            let now = Instant::now();
            let pool_failed = self.failed_until.lock().get(&host).copied();
            let lane_failed = existing.as_ref().and_then(|l| l.failed_until());
            if pool_failed.into_iter().chain(lane_failed).any(|t| now < t) {
                continue;
            }
            let lane = match existing {
                Some(lane) => lane,
                None => {
                    let lane_id = self.next_lane.fetch_add(1, Ordering::Relaxed) + 1;
                    let lane = HttpLane::new(host.clone(), lane_id, self.connector.clone(), self.timings);
                    if let Err(err) = lane.preflight().await {
                        inc(&stats().h2_errors);
                        self.failed_until.lock().insert(host.clone(), Instant::now() + self.timings.domain_cooldown);
                        log::warn!("[{label}] H2 lane={lane_id} preflight failed host={host}: {err}");
                        lane.close().await;
                        continue;
                    }
                    if self.closed.load(Ordering::Acquire) {
                        lane.close().await;
                        return None;
                    }
                    self.lanes.lock().insert(host.clone(), lane.clone());
                    lane
                }
            };
            let channel = lane.open_channel(label);
            self.balancer.update_domain_for_dc(dc, &base_domain);
            log::info!(
                "[{label}] ROUTE DC{dc} media -> H2 lane={} channel={} host={host} channels={} tcp_connections={}",
                lane.lane_id, channel.channel_id, lane.channel_count(), lane.tcp_connections.load(Ordering::Relaxed)
            );
            return Some(channel);
        }
        log::debug!("[{label}] H2 DC{dc} unavailable; using WS");
        None
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let lanes: Vec<Arc<HttpLane>> = self.lanes.lock().drain().map(|(_, l)| l).collect();
        for lane in lanes {
            lane.close().await;
        }
    }
}

enum BridgeEnd {
    Eof,
    Native(String),
    Failure(String),
}

pub async fn bridge_h2(
    reader: &mut ClientReader,
    writer: &mut ClientWriter,
    channel: Arc<HttpChannel>,
    ctx: &mut CryptoCtx,
    tag: [u8; 4],
) {
    let CryptoCtx { clt_dec, clt_enc, .. } = ctx;

    let end = {
        let upload = async {
            loop {
                let (body, quick) = match read_packet(reader, clt_dec, tag).await {
                    Ok(value) => value,
                    Err(PacketError::Eof) => return BridgeEnd::Eof,
                    Err(PacketError::Io(err)) => return BridgeEnd::Native(err.to_string()),
                    Err(PacketError::Invalid(message)) => return BridgeEnd::Failure(format!("ValueError: {message}")),
                };
                if let Err(err) = channel.send(body, quick, false).await {
                    return BridgeEnd::Failure(err.to_string());
                }
            }
        };
        let download = async {
            loop {
                let body = match channel.receive().await {
                    Ok(body) => body,
                    Err(err) => return BridgeEnd::Failure(err.to_string()),
                };
                if channel.is_closed() {
                    return BridgeEnd::Native("H2 channel closed before native response".to_string());
                }
                let encoded = match encode_reply(&body, tag) {
                    Ok(encoded) => encoded,
                    Err(message) => return BridgeEnd::Failure(format!("ValueError: {message}")),
                };
                channel.mark_delivering(true);
                let ciphertext = clt_enc.update(&encoded);
                let written = writer.write_all(&ciphertext).await;
                channel.mark_delivering(false);
                if let Err(err) = written {
                    return BridgeEnd::Native(err.to_string());
                }
                channel.delivered(body.len());
            }
        };
        let recover = async {
            channel.recover().await;
            BridgeEnd::Eof
        };
        tokio::select! {
            end = upload => end,
            end = download => end,
            end = recover => end,
        }
    };

    if let Some(code) = channel.transport_error() {
        let encoded = encode_reply(&code.to_le_bytes(), tag).unwrap_or_default();
        let ciphertext = clt_enc.update(&encoded);
        if writer.write_all(&ciphertext).await.is_ok() {
            channel.st.lock().down += 4;
            add(&stats().bytes_down, 4);
        }
    } else {
        match end {
            BridgeEnd::Eof => log::debug!("[{}] H2 channel={} native EOF", channel.label, channel.channel_id),
            BridgeEnd::Native(message) => {
                log::debug!("[{}] H2 channel={} native closed: {message}", channel.label, channel.channel_id)
            }
            BridgeEnd::Failure(message) => {
                if !channel.is_closed() {
                    log::warn!("[{}] H2 channel={} bridge ended: {message}", channel.label, channel.channel_id);
                }
            }
        }
    }
    channel.close().await;
    writer.shutdown().await;
}

pub fn spawn_detached<F>(future: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(future)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::Balancer;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct Reply {
        status: u16,
        body: Vec<u8>,
        delay: Duration,
        content_type: &'static str,
        reset: bool,
    }

    impl Reply {
        fn ok(body: Vec<u8>) -> Self {
            Self { status: 200, body, delay: Duration::ZERO, content_type: "application/octet-stream", reset: false }
        }
        fn status(status: u16) -> Self {
            Self { status, body: Vec::new(), delay: Duration::ZERO, content_type: "text/plain", reset: false }
        }
        fn delayed(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    struct Req {
        method: String,
        body: Vec<u8>,
    }

    type Handler = Arc<dyn Fn(Req) -> Reply + Send + Sync>;

    struct TestConnector {
        handler: Handler,
        connects: AtomicUsize,
        requests: Arc<AtomicUsize>,
        hang: AtomicBool,
        drop_next: Arc<AtomicBool>,
    }

    impl TestConnector {
        fn new(handler: impl Fn(Req) -> Reply + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self {
                handler: Arc::new(handler),
                connects: AtomicUsize::new(0),
                requests: Arc::new(AtomicUsize::new(0)),
                hang: AtomicBool::new(false),
                drop_next: Arc::new(AtomicBool::new(false)),
            })
        }
    }

    impl H2Connector for TestConnector {
        fn connect<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, io::Result<BoxIo>> {
            Box::pin(async move {
                self.connects.fetch_add(1, Ordering::SeqCst);
                if self.hang.load(Ordering::SeqCst) {
                    std::future::pending::<()>().await;
                }
                let (client, server) = duplex(4 * 1024 * 1024);
                let handler = self.handler.clone();
                let requests = self.requests.clone();
                let drop_next = self.drop_next.clone();
                tokio::spawn(async move {
                    let Ok(mut conn) = h2::server::handshake(server).await else { return };
                    while let Some(Ok((request, mut respond))) = conn.accept().await {
                        let handler = handler.clone();
                        let requests = requests.clone();
                        tokio::spawn(async move {
                            let method = request.method().to_string();
                            let mut body = Vec::new();
                            let mut stream = request.into_body();
                            while let Some(chunk) = stream.data().await {
                                let Ok(chunk) = chunk else { return };
                                let _ = stream.flow_control().release_capacity(chunk.len());
                                body.extend_from_slice(&chunk);
                            }
                            requests.fetch_add(1, Ordering::SeqCst);
                            let reply = handler(Req { method: method.clone(), body });
                            if !reply.delay.is_zero() {
                                tokio::time::sleep(reply.delay).await;
                            }
                            if reply.reset {
                                respond.send_reset(h2::Reason::INTERNAL_ERROR);
                                return;
                            }
                            let response = http::Response::builder()
                                .status(reply.status)
                                .header("content-type", reply.content_type)
                                .header("content-length", reply.body.len().to_string())
                                .body(())
                                .unwrap();
                            let end = method == "HEAD" || reply.body.is_empty();
                            let Ok(mut send) = respond.send_response(response, end) else { return };
                            if !end {
                                let _ = send.send_data(Bytes::from(reply.body), true);
                            }
                        });
                        if drop_next.swap(false, Ordering::SeqCst) {
                            break;
                        }
                    }
                });
                Ok(Box::new(client) as BoxIo)
            })
        }
    }

    fn fast() -> Timings {
        Timings {
            domain_cooldown: Duration::from_millis(300),
            request_timeout: Duration::from_secs(5),
            setup_timeout: Duration::from_millis(600),
            replay_idle: Duration::from_millis(20),
            replay_request: Duration::from_millis(150),
            replay_check: Duration::from_millis(20),
            replay_max_age: Duration::from_secs(10),
            replay_slot: Duration::from_millis(400),
            replay_retry: Duration::from_millis(100),
        }
    }

    fn packet(tag: u8, size: usize) -> Vec<u8> {
        let mut body = vec![tag; size];
        body[..8].copy_from_slice(&[0xAB; 8]);
        body
    }

    fn echo(request: Req) -> Reply {
        if request.method == "HEAD" {
            return Reply::status(200);
        }
        Reply::ok(request.body)
    }

    async fn lane_with(connector: Arc<TestConnector>) -> Arc<HttpLane> {
        let lane = HttpLane::new("kws2.example.test".to_string(), 1, connector, fast());
        lane.preflight().await.unwrap();
        lane
    }

    async fn receive_within(channel: &HttpChannel, ms: u64) -> Result<Vec<u8>, ChannelError> {
        tokio::time::timeout(Duration::from_millis(ms), channel.receive())
            .await
            .expect("receive timed out")
    }

    #[tokio::test]
    async fn preflight_accepts_head_200_405_and_501_but_rejects_404() {
        for (status, ok) in [(200u16, true), (405, true), (501, true), (404, false), (503, false)] {
            let connector = TestConnector::new(move |_| Reply::status(status));
            let lane = HttpLane::new("kws2.example.test".to_string(), 1, connector, fast());
            assert_eq!(lane.preflight().await.is_ok(), ok, "status {status}");
        }
    }

    #[tokio::test]
    async fn channel_roundtrip_returns_reply_and_releases_capacity() {
        let lane = lane_with(TestConnector::new(echo)).await;
        let channel = lane.open_channel("t");
        assert!(channel.send(packet(1, 64), false, false).await.unwrap());
        assert_eq!(receive_within(&channel, 2000).await.unwrap(), packet(1, 64));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(channel.pending_len(), 0);
        assert_eq!(lane.inflight().0, 0);
        assert_eq!(lane.reply_buffer_bytes(), 0);
        channel.close().await;
        assert_eq!(lane.channel_count(), 0);
    }

    #[tokio::test]
    async fn large_upload_and_download_cross_flow_control_windows() {
        let lane = lane_with(TestConnector::new(echo)).await;
        let channel = lane.open_channel("t");
        let big = packet(7, 3 * 1024 * 1024);
        assert!(channel.send(big.clone(), false, false).await.unwrap());
        assert_eq!(receive_within(&channel, 5000).await.unwrap(), big);
        channel.close().await;
    }

    #[tokio::test]
    async fn channels_on_one_lane_keep_replies_separate_with_same_auth_prefix() {
        let lane = lane_with(TestConnector::new(|r| {
            if r.method == "HEAD" {
                return Reply::status(200);
            }
            let delay = if r.body[8] == 1 { 80 } else { 0 };
            Reply::ok(r.body).delayed(Duration::from_millis(delay))
        }))
        .await;
        let first = lane.open_channel("a");
        let second = lane.open_channel("b");
        first.send(packet(1, 32), false, false).await.unwrap();
        second.send(packet(2, 32), false, false).await.unwrap();
        assert_eq!(receive_within(&second, 2000).await.unwrap(), packet(2, 32));
        assert_eq!(receive_within(&first, 2000).await.unwrap(), packet(1, 32));
        first.close().await;
        assert!(!second.is_closed());
        second.send(packet(3, 32), false, false).await.unwrap();
        assert_eq!(receive_within(&second, 2000).await.unwrap(), packet(3, 32));
        second.close().await;
    }

    #[tokio::test]
    async fn http_404_is_forwarded_as_transport_error_without_cooling_the_lane() {
        let lane = lane_with(TestConnector::new(|r| {
            if r.method == "HEAD" { Reply::status(200) } else { Reply::status(404) }
        }))
        .await;
        let channel = lane.open_channel("t");
        channel.send(packet(1, 32), false, false).await.unwrap();
        let err = receive_within(&channel, 2000).await.unwrap_err();
        assert!(matches!(err, ChannelError::Transport(-404)));
        assert_eq!(channel.transport_error(), Some(-404));
        assert!(lane.failed_until().is_none());
    }

    #[tokio::test]
    async fn binary_transport_error_payload_is_terminal() {
        let lane = lane_with(TestConnector::new(|r| {
            if r.method == "HEAD" { Reply::status(200) } else { Reply::ok((-429i32).to_le_bytes().to_vec()) }
        }))
        .await;
        let channel = lane.open_channel("t");
        channel.send(packet(1, 32), false, false).await.unwrap();
        assert!(matches!(receive_within(&channel, 2000).await, Err(ChannelError::Transport(-429))));
        assert!(lane.failed_until().is_none());
    }

    #[tokio::test]
    async fn html_and_misaligned_bodies_fail_the_channel_and_cool_the_lane() {
        for case in 0..2 {
            let lane = lane_with(TestConnector::new(move |r| {
                if r.method == "HEAD" {
                    return Reply::status(200);
                }
                if case == 0 {
                    let mut reply = Reply::ok(b"<html>".to_vec());
                    reply.content_type = "text/html; charset=utf-8";
                    reply
                } else {
                    Reply::ok(vec![1, 2, 3])
                }
            }))
            .await;
            let channel = lane.open_channel("t");
            channel.send(packet(1, 32), false, false).await.unwrap();
            assert!(matches!(receive_within(&channel, 2000).await, Err(ChannelError::Other(_))));
            assert!(lane.failed_until().is_some());
        }
    }

    #[tokio::test]
    async fn peer_reset_fails_only_its_channel() {
        let lane = lane_with(TestConnector::new(|r| {
            if r.method == "HEAD" {
                return Reply::status(200);
            }
            let mut reply = Reply::ok(r.body.clone());
            reply.reset = r.body[8] == 9;
            reply
        }))
        .await;
        let bad = lane.open_channel("bad");
        let good = lane.open_channel("good");
        bad.send(packet(9, 32), false, false).await.unwrap();
        good.send(packet(1, 32), false, false).await.unwrap();
        assert!(receive_within(&bad, 2000).await.is_err());
        assert_eq!(receive_within(&good, 2000).await.unwrap(), packet(1, 32));
    }

    #[tokio::test]
    async fn connection_loss_reconnects_on_next_request() {
        let connector = TestConnector::new(echo);
        let lane = lane_with(connector.clone()).await;
        connector.drop_next.store(true, Ordering::SeqCst);
        let channel = lane.open_channel("t");
        channel.send(packet(1, 32), false, false).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(500), channel.receive()).await;
        channel.close().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let channel = lane.open_channel("t2");
        channel.send(packet(2, 32), false, false).await.unwrap();
        assert_eq!(receive_within(&channel, 3000).await.unwrap(), packet(2, 32));
        assert!(connector.connects.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn close_cancels_pending_requests_and_returns_capacity() {
        let lane = lane_with(TestConnector::new(|r| {
            if r.method == "HEAD" {
                return Reply::status(200);
            }
            Reply::ok(r.body).delayed(Duration::from_secs(30))
        }))
        .await;
        let channel = lane.open_channel("t");
        channel.send(packet(1, 64), false, false).await.unwrap();
        channel.send(packet(2, 64), false, false).await.unwrap();
        assert_eq!(lane.inflight().0, 2);
        channel.close().await;
        assert_eq!(lane.inflight().0, 0);
        assert_eq!(channel.pending_len(), 0);
        assert!(matches!(channel.send(packet(3, 64), false, false).await, Err(ChannelError::Closed)));
    }

    #[tokio::test]
    async fn stalled_original_is_replayed_with_identical_ciphertext() {
        let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let seen_handler = seen.clone();
        let lane = lane_with(TestConnector::new(move |r| {
            if r.method == "HEAD" {
                return Reply::status(200);
            }
            let attempt = {
                let mut seen = seen_handler.lock();
                seen.push(r.body.clone());
                seen.len()
            };
            if attempt == 1 {
                Reply::ok(Vec::new()).delayed(Duration::from_secs(30))
            } else {
                Reply::ok(r.body)
            }
        }))
        .await;
        let channel = lane.open_channel("t");
        let recover = {
            let channel = channel.clone();
            tokio::spawn(async move { channel.recover().await })
        };
        channel.send(packet(5, 48), false, false).await.unwrap();
        assert_eq!(receive_within(&channel, 4000).await.unwrap(), packet(5, 48));
        {
            let seen = seen.lock();
            assert!(seen.len() >= 2);
            assert!(seen.iter().all(|b| *b == packet(5, 48)));
        }
        assert!(channel.replay_requests() >= 1);
        channel.close().await;
        recover.abort();
    }

    #[tokio::test]
    async fn handshake_packets_with_zero_prefix_are_never_replayed() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_handler = count.clone();
        let lane = lane_with(TestConnector::new(move |r| {
            if r.method == "HEAD" {
                return Reply::status(200);
            }
            count_handler.fetch_add(1, Ordering::SeqCst);
            Reply::ok(Vec::new()).delayed(Duration::from_secs(30))
        }))
        .await;
        let channel = lane.open_channel("t");
        let recover = {
            let channel = channel.clone();
            tokio::spawn(async move { channel.recover().await })
        };
        let mut handshake = vec![0u8; 48];
        handshake[10] = 1;
        channel.send(handshake, false, false).await.unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(channel.replay_requests(), 0);
        channel.close().await;
        recover.abort();
    }

    #[tokio::test]
    async fn replay_budget_is_bounded_when_replies_never_help() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_handler = count.clone();
        let lane = lane_with(TestConnector::new(move |r| {
            if r.method == "HEAD" {
                return Reply::status(200);
            }
            count_handler.fetch_add(1, Ordering::SeqCst);
            Reply::ok(Vec::new())
        }))
        .await;
        let channel = lane.open_channel("t");
        let recover = {
            let channel = channel.clone();
            tokio::spawn(async move { channel.recover().await })
        };
        channel.send(packet(5, 48), false, false).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let total = count.load(Ordering::SeqCst);
        assert!(total >= 2 && total <= 1 + REPLAY_MAX_ATTEMPTS as usize, "total={total}");
        channel.close().await;
        recover.abort();
    }

    #[tokio::test]
    async fn queue_overflow_closes_only_the_slow_channel() {
        let lane = lane_with(TestConnector::new(echo)).await;
        let slow = lane.open_channel("slow");
        let other = lane.open_channel("other");
        for i in 0..40u8 {
            if slow.send(packet(i, 32), false, false).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(slow.is_closed());
        other.send(packet(99, 32), false, false).await.unwrap();
        assert_eq!(receive_within(&other, 2000).await.unwrap(), packet(99, 32));
    }

    #[tokio::test]
    async fn channel_request_bound_makes_senders_wait_instead_of_dropping() {
        let lane = lane_with(TestConnector::new(|r| {
            if r.method == "HEAD" {
                return Reply::status(200);
            }
            Reply::ok(r.body).delayed(Duration::from_millis(120))
        }))
        .await;
        let channel = lane.open_channel("t");
        let consumer = {
            let channel = channel.clone();
            tokio::spawn(async move {
                let mut got = 0;
                while got < 12 {
                    if channel.receive().await.is_err() {
                        break;
                    }
                    got += 1;
                }
                got
            })
        };
        for i in 0..12u8 {
            channel.send(packet(i, 32), false, false).await.unwrap();
            assert!(channel.pending_len() <= MAX_CHANNEL_REQUESTS);
        }
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), consumer).await.unwrap().unwrap(), 12);
        channel.close().await;
    }

    #[tokio::test]
    async fn pool_opens_lane_once_for_simultaneous_requests() {
        let connector = TestConnector::new(echo);
        let balancer = Arc::new(Balancer::new());
        balancer.update_domains_list(&["one.example.test".to_string()]);
        let pool = CfH2Pool::with_connector(balancer, connector.clone(), fast());
        let (a, b, c) = tokio::join!(pool.open(2, "a"), pool.open(2, "b"), pool.open(2, "c"));
        assert!(a.is_some() && b.is_some() && c.is_some());
        assert_eq!(pool.lane_count(), 1);
        assert_eq!(connector.connects.load(Ordering::SeqCst), 1);
        pool.close().await;
    }

    #[tokio::test]
    async fn pool_falls_back_when_preflight_fails_and_cools_the_domain() {
        let connector = TestConnector::new(|_| Reply::status(404));
        let balancer = Arc::new(Balancer::new());
        balancer.update_domains_list(&["one.example.test".to_string()]);
        let pool = CfH2Pool::with_connector(balancer, connector.clone(), fast());
        assert!(pool.open(2, "a").await.is_none());
        assert_eq!(pool.lane_count(), 0);
        let connects = connector.connects.load(Ordering::SeqCst);
        assert!(pool.open(2, "b").await.is_none());
        assert_eq!(connector.connects.load(Ordering::SeqCst), connects);
    }

    #[tokio::test]
    async fn pool_setup_timeout_returns_to_ws_and_backs_off() {
        let connector = TestConnector::new(echo);
        connector.hang.store(true, Ordering::SeqCst);
        let balancer = Arc::new(Balancer::new());
        balancer.update_domains_list(&["one.example.test".to_string()]);
        let pool = CfH2Pool::with_connector(balancer, connector.clone(), fast());
        assert!(pool.open(2, "a").await.is_none());
        assert_eq!(pool.lane_count(), 0);
        let before = connector.connects.load(Ordering::SeqCst);
        assert!(pool.open(2, "b").await.is_none());
        assert_eq!(connector.connects.load(Ordering::SeqCst), before);
    }

    #[tokio::test]
    async fn closed_pool_cannot_open_channels() {
        let balancer = Arc::new(Balancer::new());
        balancer.update_domains_list(&["one.example.test".to_string()]);
        let pool = CfH2Pool::with_connector(balancer, TestConnector::new(echo), fast());
        pool.close().await;
        assert!(pool.open(2, "a").await.is_none());
    }

    #[tokio::test]
    async fn unsupported_dc_is_skipped() {
        let balancer = Arc::new(Balancer::new());
        balancer.update_domains_list(&["one.example.test".to_string()]);
        let pool = CfH2Pool::with_connector(balancer, TestConnector::new(echo), fast());
        assert!(pool.open(77, "a").await.is_none());
    }

    struct Pair {
        reader: ClientReader,
        peer: TcpStream,
        server_writer: ClientWriter,
    }

    async fn tcp_pair() -> Pair {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted, peer) = tokio::join!(listener.accept(), TcpStream::connect(addr));
        let (read_half, write_half) = accepted.unwrap().0.into_split();
        Pair {
            reader: ClientReader::Plain(read_half),
            peer: peer.unwrap(),
            server_writer: ClientWriter::Plain(write_half),
        }
    }

    fn cipher_pair() -> (AesCtr, AesCtr) {
        (AesCtr::new(&[5u8; 32], &[6u8; 16]), AesCtr::new(&[5u8; 32], &[6u8; 16]))
    }

    async fn feed(pair: &mut Pair, plain: &[u8], enc: &mut AesCtr) {
        pair.peer.write_all(&enc.update(plain)).await.unwrap();
    }

    fn abridged_frame(payload: &[u8], quick: bool) -> Vec<u8> {
        let words = payload.len() / 4;
        let mut out = if words < 0x7f {
            vec![words as u8 | if quick { 0x80 } else { 0 }]
        } else {
            let mut v = vec![0x7f | if quick { 0x80 } else { 0 }];
            v.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
            v
        };
        out.extend_from_slice(payload);
        out
    }

    fn intermediate_frame(payload: &[u8], quick: bool) -> Vec<u8> {
        let mut length = payload.len() as u32;
        if quick {
            length |= 0x8000_0000;
        }
        let mut out = length.to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    async fn read_one(tag: [u8; 4], wire: Vec<u8>) -> Result<(Vec<u8>, bool), PacketError> {
        let mut pair = tcp_pair().await;
        let (mut enc, mut dec) = cipher_pair();
        feed(&mut pair, &wire, &mut enc).await;
        let result = tokio::time::timeout(Duration::from_secs(2), read_packet(&mut pair.reader, &mut dec, tag)).await;
        drop(pair.peer);
        drop(pair.server_writer);
        result.expect("read_packet hung")
    }

    #[tokio::test]
    async fn native_framing_abridged_and_intermediate_with_quick_ack() {
        for (size, quick) in [(24usize, false), (512, true), (4096, false)] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (body, got_quick) = read_one(PROTO_TAG_ABRIDGED, abridged_frame(&payload, quick)).await.unwrap();
            assert_eq!((body, got_quick), (payload.clone(), quick));
            let (body, got_quick) = read_one([0xee; 4], intermediate_frame(&payload, quick)).await.unwrap();
            assert_eq!((body, got_quick), (payload, quick));
        }
    }

    #[tokio::test]
    async fn padded_plaintext_removes_all_fifteen_padding_lengths() {
        for padding in 0..16usize {
            let mut payload = vec![0u8; 24 + 16 * 2];
            payload[0] = 1;
            let mut wire_body = payload.clone();
            wire_body.extend(std::iter::repeat(0xEE).take(padding));
            if padding == 16 {
                continue;
            }
            let (body, _) = read_one(PROTO_TAG_SECURE, intermediate_frame(&wire_body, false)).await.unwrap();
            assert_eq!(body, payload, "padding={padding}");
        }
    }

    #[tokio::test]
    async fn plaintext_accepts_extended_padding() {
        let mut payload = vec![0u8; 32];
        payload[16..20].copy_from_slice(&8u32.to_le_bytes());
        let packet_len = 20 + 8;
        let mut wire_body = payload[..packet_len].to_vec();
        wire_body.extend(std::iter::repeat(0xAA).take(200));
        let (body, _) = read_one(PROTO_TAG_SECURE, intermediate_frame(&wire_body, false)).await.unwrap();
        assert_eq!(body.len(), packet_len);
    }

    #[tokio::test]
    async fn invalid_lengths_and_excess_padding_are_rejected() {
        let short = intermediate_frame(&[1u8; 20], false);
        assert!(matches!(read_one([0xee; 4], short).await, Err(PacketError::Invalid(_))));
        let mut huge = ((MAX_PACKET + 4) as u32).to_le_bytes().to_vec();
        huge.extend_from_slice(&[0u8; 8]);
        assert!(matches!(read_one([0xee; 4], huge).await, Err(PacketError::Invalid(_))));
        let mut plain_prefixed = vec![0u8; 28];
        plain_prefixed[16..20].copy_from_slice(&8u32.to_le_bytes());
        plain_prefixed.extend(std::iter::repeat(0u8).take(300));
        assert!(matches!(
            read_one(PROTO_TAG_SECURE, intermediate_frame(&plain_prefixed, false)).await,
            Err(PacketError::Invalid(_))
        ));
        let mut misaligned = vec![1u8; 26];
        misaligned[0] = 1;
        assert!(matches!(
            read_one([0xee; 4], intermediate_frame(&misaligned, false)).await,
            Err(PacketError::Invalid(_))
        ));
    }

    #[test]
    fn encode_reply_framing_and_validation() {
        let body = vec![9u8; 16];
        assert_eq!(encode_reply(&body, PROTO_TAG_ABRIDGED).unwrap(), [vec![4u8], body.clone()].concat());
        let intermediate = encode_reply(&body, [0xee; 4]).unwrap();
        assert_eq!(&intermediate[..4], &16u32.to_le_bytes());
        for _ in 0..30 {
            let secure = encode_reply(&body, PROTO_TAG_SECURE).unwrap();
            let declared = u32::from_le_bytes(secure[..4].try_into().unwrap()) as usize;
            assert_eq!(secure.len(), 4 + declared);
            assert!((16..20).contains(&declared));
        }
        let big = vec![0u8; 0x7f * 4];
        assert_eq!(&encode_reply(&big, PROTO_TAG_ABRIDGED).unwrap()[..4], &[0x7f, 0x7f, 0, 0]);
        assert!(encode_reply(&[], PROTO_TAG_ABRIDGED).is_err());
        assert!(encode_reply(&[1, 2, 3], PROTO_TAG_ABRIDGED).is_err());
        assert_eq!(
            encode_reply(&(-404i32).to_le_bytes(), PROTO_TAG_ABRIDGED).unwrap(),
            [vec![1u8], (-404i32).to_le_bytes().to_vec()].concat()
        );
    }

    #[tokio::test]
    async fn bridge_delivers_replies_and_terminal_transport_error_to_native_client() {
        for transport_error in [false, true] {
            let lane = lane_with(TestConnector::new(move |r| {
                if r.method == "HEAD" {
                    return Reply::status(200);
                }
                if transport_error {
                    return Reply::status(404);
                }
                let mut reply = r.body.clone();
                reply.reverse();
                Reply::ok(reply)
            }))
            .await;
            let channel = lane.open_channel("t");
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));
            let (read_half, write_half) = accepted.unwrap().0.into_split();
            let mut client = client.unwrap();
            let mut ctx = CryptoCtx {
                clt_dec: AesCtr::new(&[5u8; 32], &[6u8; 16]),
                clt_enc: AesCtr::new(&[8u8; 32], &[9u8; 16]),
                tg_enc: AesCtr::new(&[1u8; 32], &[1u8; 16]),
                tg_dec: AesCtr::new(&[1u8; 32], &[1u8; 16]),
            };
            let bridge = tokio::spawn(async move {
                let mut reader = ClientReader::Plain(read_half);
                let mut writer = ClientWriter::Plain(write_half);
                bridge_h2(&mut reader, &mut writer, channel, &mut ctx, PROTO_TAG_ABRIDGED).await;
            });
            let payload: Vec<u8> = (0..32u8).collect();
            let mut client_enc = AesCtr::new(&[5u8; 32], &[6u8; 16]);
            client.write_all(&client_enc.update(&abridged_frame(&payload, false))).await.unwrap();
            let mut client_dec = AesCtr::new(&[8u8; 32], &[9u8; 16]);
            if transport_error {
                let mut got = [0u8; 5];
                tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut got)).await.unwrap().unwrap();
                let plain = client_dec.update(&got);
                assert_eq!(plain[0], 1);
                assert_eq!(i32::from_le_bytes(plain[1..5].try_into().unwrap()), -404);
            } else {
                let mut got = vec![0u8; 1 + payload.len()];
                tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut got)).await.unwrap().unwrap();
                let plain = client_dec.update(&got);
                let mut expected = payload.clone();
                expected.reverse();
                assert_eq!(plain[0] as usize, payload.len() / 4);
                assert_eq!(&plain[1..], &expected[..]);
            }
            drop(client);
            tokio::time::timeout(Duration::from_secs(3), bridge).await.unwrap().unwrap();
            assert_eq!(lane.channel_count(), 0);
        }
    }
}
