use std::collections::BTreeSet;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::config::{coerce_domain_list, parse_dc_ip_list, random_secret, DcIpErrorKind, ProxyConfig};
use crate::i18n::{detect_system_language, tf, t};
use crate::utils::get_link_host;

pub const APP_NAME: &str = "TgWsProxy";
pub const PORTABLE_DIR_NAME: &str = "TgWsProxy_data";
pub const UI_ONLY_KEYS: [&str; 4] = ["appearance", "accent", "autostart", "language"];

#[derive(Debug, Clone, PartialEq)]
pub struct AppConfig {
    pub port: u16,
    pub host: String,
    pub secret: String,
    pub dc_ip: Vec<String>,
    pub verbose: bool,
    pub log_max_mb: f64,
    pub buf_kb: i64,
    pub pool_size: i64,
    pub cfproxy: bool,
    pub h2: bool,
    pub cfproxy_user_domain_enabled: bool,
    pub cfproxy_user_domain: Vec<String>,
    pub cfproxy_worker_enabled: bool,
    pub cfproxy_worker_domain: Vec<String>,
    pub force_test_dc: bool,
    pub no_secure: bool,
    pub appearance: String,
    pub accent: String,
    pub language: String,
    pub autostart: bool,
    pub extra: Map<String, Value>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            port: 1443,
            host: "127.0.0.1".to_string(),
            secret: random_secret(),
            dc_ip: vec!["2:149.154.167.220".to_string(), "4:149.154.167.220".to_string()],
            verbose: false,
            log_max_mb: 5.0,
            buf_kb: 256,
            pool_size: 4,
            cfproxy: true,
            h2: true,
            cfproxy_user_domain_enabled: false,
            cfproxy_user_domain: Vec::new(),
            cfproxy_worker_enabled: false,
            cfproxy_worker_domain: Vec::new(),
            force_test_dc: false,
            no_secure: false,
            appearance: "auto".to_string(),
            accent: "telegram".to_string(),
            language: detect_system_language().code().to_string(),
            autostart: false,
            extra: Map::new(),
        }
    }
}

const KNOWN_KEYS: [&str; 20] = [
    "port", "host", "secret", "dc_ip", "verbose", "log_max_mb", "buf_kb", "pool_size", "cfproxy", "h2",
    "cfproxy_user_domain_enabled", "cfproxy_user_domain", "cfproxy_worker_enabled", "cfproxy_worker_domain",
    "force_test_dc", "no_secure", "appearance", "accent", "language", "autostart",
];

fn get_bool(map: &Map<String, Value>, key: &str, default: bool) -> bool {
    map.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn get_string(map: &Map<String, Value>, key: &str, default: &str) -> String {
    map.get(key).and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| default.to_string())
}

fn get_int(map: &Map<String, Value>, key: &str, default: i64) -> i64 {
    match map.get(key) {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(default),
        _ => default,
    }
}

impl AppConfig {
    pub fn from_value(value: &Value) -> AppConfig {
        let defaults = AppConfig::default();
        let Some(map) = value.as_object() else { return defaults };
        let user_domains = coerce_domain_list(map.get("cfproxy_user_domain").unwrap_or(&Value::Null));
        let worker_domains = coerce_domain_list(map.get("cfproxy_worker_domain").unwrap_or(&Value::Null));
        let dc_ip = match map.get("dc_ip") {
            Some(Value::Array(items)) => items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => defaults.dc_ip.clone(),
        };
        let port = get_int(map, "port", defaults.port as i64);
        let extra: Map<String, Value> = map
            .iter()
            .filter(|(k, _)| !KNOWN_KEYS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        AppConfig {
            port: if (1..=65535).contains(&port) { port as u16 } else { defaults.port },
            host: get_string(map, "host", &defaults.host),
            secret: get_string(map, "secret", &defaults.secret),
            dc_ip,
            verbose: get_bool(map, "verbose", defaults.verbose),
            log_max_mb: map.get("log_max_mb").and_then(Value::as_f64).unwrap_or(defaults.log_max_mb),
            buf_kb: get_int(map, "buf_kb", defaults.buf_kb),
            pool_size: get_int(map, "pool_size", defaults.pool_size),
            cfproxy: get_bool(map, "cfproxy", defaults.cfproxy),
            h2: get_bool(map, "h2", defaults.h2),
            cfproxy_user_domain_enabled: get_bool(map, "cfproxy_user_domain_enabled", !user_domains.is_empty()),
            cfproxy_user_domain: user_domains,
            cfproxy_worker_enabled: get_bool(map, "cfproxy_worker_enabled", !worker_domains.is_empty()),
            cfproxy_worker_domain: worker_domains,
            force_test_dc: get_bool(map, "force_test_dc", defaults.force_test_dc),
            no_secure: get_bool(map, "no_secure", defaults.no_secure),
            appearance: get_string(map, "appearance", &defaults.appearance),
            accent: get_string(map, "accent", &defaults.accent),
            language: get_string(map, "language", &defaults.language),
            autostart: get_bool(map, "autostart", defaults.autostart),
            extra,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut map = self.extra.clone();
        map.insert("port".into(), json!(self.port));
        map.insert("host".into(), json!(self.host));
        map.insert("dc_ip".into(), json!(self.dc_ip));
        map.insert("verbose".into(), json!(self.verbose));
        map.insert("log_max_mb".into(), json!(self.log_max_mb));
        map.insert("buf_kb".into(), json!(self.buf_kb));
        map.insert("pool_size".into(), json!(self.pool_size));
        map.insert("cfproxy".into(), json!(self.cfproxy));
        map.insert("h2".into(), json!(self.h2));
        map.insert("cfproxy_user_domain_enabled".into(), json!(self.cfproxy_user_domain_enabled));
        map.insert("cfproxy_user_domain".into(), json!(self.cfproxy_user_domain));
        map.insert("cfproxy_worker_enabled".into(), json!(self.cfproxy_worker_enabled));
        map.insert("cfproxy_worker_domain".into(), json!(self.cfproxy_worker_domain));
        map.insert("force_test_dc".into(), json!(self.force_test_dc));
        map.insert("no_secure".into(), json!(self.no_secure));
        map.insert("appearance".into(), json!(self.appearance));
        map.insert("accent".into(), json!(self.accent));
        map.insert("secret".into(), json!(self.secret));
        map.insert("language".into(), json!(self.language));
        map.insert("autostart".into(), json!(self.autostart));
        Value::Object(map)
    }

    pub fn load(path: &Path) -> AppConfig {
        match std::fs::read_to_string(path).ok().and_then(|text| serde_json::from_str::<Value>(&text).ok()) {
            Some(value) if value.is_object() => AppConfig::from_value(&value),
            Some(_) | None => {
                if path.exists() {
                    log::warn!("Failed to load config {}", path.display());
                }
                AppConfig::default()
            }
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(&self.to_value()).map_err(io::Error::other)?;
        std::fs::write(path, text)
    }

    pub fn to_proxy_config(&self) -> Result<ProxyConfig, String> {
        let dc_redirects = parse_dc_ip_list(&self.dc_ip).map_err(|e| e.to_string())?;
        Ok(ProxyConfig {
            port: self.port,
            host: self.host.clone(),
            secret: self.secret.clone(),
            dc_redirects,
            buffer_size: (self.buf_kb.max(4) as usize) * 1024,
            pool_size: self.pool_size.max(0) as usize,
            fallback_cfproxy: self.cfproxy,
            cfproxy_user_domains: if self.cfproxy_user_domain_enabled { self.cfproxy_user_domain.clone() } else { Vec::new() },
            cfproxy_worker_domains: if self.cfproxy_worker_enabled { self.cfproxy_worker_domain.clone() } else { Vec::new() },
            cfproxy_h2_media: self.h2,
            disable_secure: self.no_secure,
            fake_tls_domain: String::new(),
            proxy_protocol: false,
            force_test_dc: self.force_test_dc,
        })
    }

    pub fn tg_proxy_url(&self) -> String {
        format!(
            "tg://proxy?server={}&port={}&secret=dd{}",
            get_link_host(&self.host),
            self.port,
            self.secret
        )
    }

    pub fn changed_keys(&self, other: &AppConfig) -> BTreeSet<String> {
        let (a, b) = (self.to_value(), other.to_value());
        let (a, b) = (a.as_object().expect("object"), b.as_object().expect("object"));
        let mut keys: BTreeSet<String> = BTreeSet::new();
        for key in a.keys().chain(b.keys()) {
            if a.get(key) != b.get(key) {
                keys.insert(key.clone());
            }
        }
        keys
    }
}

pub fn requires_restart(changed: &BTreeSet<String>) -> bool {
    changed.iter().any(|key| !UI_ONLY_KEYS.contains(&key.as_str()))
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FormValues {
    pub host: String,
    pub port: String,
    pub secret: String,
    pub dc_ip: String,
    pub verbose: bool,
    pub buf_kb: String,
    pub pool_size: String,
    pub log_max_mb: String,
    pub cfproxy: bool,
    pub h2: bool,
    pub cfproxy_user_domain_enabled: bool,
    pub cfproxy_user_domain: String,
    pub cfproxy_worker_enabled: bool,
    pub cfproxy_worker_domain: String,
    pub force_test_dc: bool,
    pub no_secure: bool,
    pub appearance: String,
    pub accent: String,
    pub language: String,
    pub autostart: bool,
}

impl FormValues {
    pub fn from_config(cfg: &AppConfig) -> FormValues {
        FormValues {
            host: cfg.host.clone(),
            port: cfg.port.to_string(),
            secret: cfg.secret.clone(),
            dc_ip: cfg.dc_ip.join("\n"),
            verbose: cfg.verbose,
            buf_kb: cfg.buf_kb.to_string(),
            pool_size: cfg.pool_size.to_string(),
            log_max_mb: format_number(cfg.log_max_mb),
            cfproxy: cfg.cfproxy,
            h2: cfg.h2,
            cfproxy_user_domain_enabled: cfg.cfproxy_user_domain_enabled,
            cfproxy_user_domain: cfg.cfproxy_user_domain.join(", "),
            cfproxy_worker_enabled: cfg.cfproxy_worker_enabled,
            cfproxy_worker_domain: cfg.cfproxy_worker_domain.join(", "),
            force_test_dc: cfg.force_test_dc,
            no_secure: cfg.no_secure,
            appearance: cfg.appearance.clone(),
            accent: cfg.accent.clone(),
            language: cfg.language.clone(),
            autostart: cfg.autostart,
        }
    }
}

pub fn format_number(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

pub fn inet_aton(text: &str) -> Option<Ipv4Addr> {
    if text.is_empty() || text.len() > 64 {
        return None;
    }
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let mut values = Vec::with_capacity(parts.len());
    for part in &parts {
        if part.is_empty() {
            return None;
        }
        let parsed = if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()?
        } else if part.len() > 1 && part.starts_with('0') {
            u64::from_str_radix(&part[1..], 8).ok()?
        } else {
            part.parse::<u64>().ok()?
        };
        values.push(parsed);
    }
    let last = values.pop()?;
    let mut address: u64 = 0;
    for (index, value) in values.iter().enumerate() {
        if *value > 255 {
            return None;
        }
        address |= value << (24 - 8 * index);
    }
    let remaining_bits = 32 - 8 * values.len() as u32;
    if remaining_bits < 32 && last >= (1u64 << remaining_bits) {
        return None;
    }
    if last > u32::MAX as u64 {
        return None;
    }
    address |= last;
    Some(Ipv4Addr::from(address as u32))
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FieldErrors {
    pub host: Option<String>,
    pub port: Option<String>,
    pub dc: Option<String>,
    pub secret: Option<String>,
}

impl FieldErrors {
    pub fn first(&self) -> Option<&String> {
        self.host.as_ref().or(self.port.as_ref()).or(self.dc.as_ref()).or(self.secret.as_ref())
    }

    pub fn any(&self) -> bool {
        self.first().is_some()
    }
}

pub fn field_errors(values: &FormValues) -> FieldErrors {
    let mut errors = FieldErrors::default();
    if inet_aton(values.host.trim()).is_none() {
        errors.host = Some(t("validation.bad_host"));
    }
    match values.port.trim().parse::<u32>() {
        Ok(port) if (1..=65535).contains(&port) => {}
        _ => errors.port = Some(t("validation.bad_port")),
    }
    let lines: Vec<String> = values
        .dc_ip
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if let Err(err) = parse_dc_ip_list(&lines) {
        let key = if err.kind == DcIpErrorKind::Format { "validation.dc_format" } else { "validation.dc_invalid" };
        errors.dc = Some(tf(key, &[("entry", &err.entry)]));
    }
    let secret = values.secret.trim();
    if secret.chars().count() != 32 {
        errors.secret = Some(t("validation.bad_secret_len"));
    } else if !secret.chars().all(|c| c.is_ascii_hexdigit()) {
        errors.secret = Some(t("validation.bad_secret_hex"));
    }
    errors
}

pub fn link_from_form(values: &FormValues) -> Option<String> {
    let errors = field_errors(values);
    if errors.host.is_some() || errors.port.is_some() || errors.secret.is_some() {
        return None;
    }
    Some(format!(
        "tg://proxy?server={}&port={}&secret=dd{}",
        get_link_host(values.host.trim()),
        values.port.trim(),
        values.secret.trim()
    ))
}

pub fn validate_settings(values: &FormValues, base: &AppConfig, defaults: &AppConfig) -> Result<AppConfig, String> {
    let errors = field_errors(values);
    if let Some(message) = errors.first() {
        return Err(message.clone());
    }
    let host = values.host.trim().to_string();
    let port: u32 = values.port.trim().parse().map_err(|_| t("validation.bad_port"))?;
    let lines: Vec<String> = values
        .dc_ip
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    let secret = values.secret.trim().to_string();

    let number = |text: &str| -> Option<f64> { text.trim().parse::<f64>().ok().filter(|v| v.is_finite()) };
    let mut config = base.clone();
    config.host = host;
    config.port = port as u16;
    config.secret = secret;
    config.dc_ip = lines;
    config.buf_kb = number(&values.buf_kb).map(|v| v as i64).unwrap_or(defaults.buf_kb);
    config.pool_size = number(&values.pool_size).map(|v| v as i64).unwrap_or(defaults.pool_size);
    config.log_max_mb = number(&values.log_max_mb).unwrap_or(defaults.log_max_mb);
    config.verbose = values.verbose;
    config.cfproxy = values.cfproxy;
    config.h2 = values.h2;
    config.cfproxy_user_domain_enabled = values.cfproxy_user_domain_enabled;
    config.cfproxy_user_domain = crate::config::coerce_domain_text(&values.cfproxy_user_domain);
    config.cfproxy_worker_enabled = values.cfproxy_worker_enabled;
    config.cfproxy_worker_domain = crate::config::coerce_domain_text(&values.cfproxy_worker_domain);
    config.force_test_dc = values.force_test_dc;
    config.no_secure = values.no_secure;
    config.appearance = values.appearance.clone();
    config.accent = values.accent.clone();
    config.language = values.language.clone();
    config.autostart = values.autostart;
    Ok(config)
}

pub fn exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from(APP_NAME))
}

fn standard_app_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(APP_NAME)
}

fn migrate_into_portable(portable: &Path) {
    let Ok(mut existing) = std::fs::read_dir(portable) else { return };
    if existing.next().is_some() {
        return;
    }
    let standard = standard_app_dir();
    let Ok(entries) = std::fs::read_dir(&standard) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().contains(".log") {
            continue;
        }
        let source = entry.path();
        if source.is_file() {
            if let Err(err) = std::fs::copy(&source, portable.join(&name)) {
                log::warn!("Portable migration: skip {}: {err}", name.to_string_lossy());
            }
        }
    }
}

pub fn app_dir() -> PathBuf {
    if let Some(dir) = exe_path().parent() {
        let portable = dir.join(PORTABLE_DIR_NAME);
        if std::env::args().any(|a| a == "--portable") && std::fs::create_dir_all(&portable).is_err() {
            return standard_app_dir();
        }
        if portable.is_dir() {
            migrate_into_portable(&portable);
            return portable;
        }
    }
    standard_app_dir()
}

pub struct AppPaths {
    pub dir: PathBuf,
    pub config: PathBuf,
    pub log: PathBuf,
    pub first_run_marker: PathBuf,
    pub ipv6_marker: PathBuf,
}

impl AppPaths {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            config: dir.join("config.json"),
            log: dir.join("proxy.log"),
            first_run_marker: dir.join(".first_run_done_mtproto"),
            ipv6_marker: dir.join(".ipv6_warned"),
            dir,
        }
    }

    pub fn detect() -> Self {
        Self::new(app_dir())
    }

    pub fn ensure(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)
    }
}

pub fn diagnose_listen_error(err: &io::Error) -> Option<(String, Option<&'static str>)> {
    const WSAEACCES: i32 = 10013;
    const WSAEFAULT: i32 = 10014;
    const WSAEADDRINUSE: i32 = 10048;
    const WSAEADDRNOTAVAIL: i32 = 10049;
    let os = err.raw_os_error();
    if err.kind() == io::ErrorKind::AddrInUse || os == Some(WSAEADDRINUSE) {
        return Some((t("diagnostics.port_busy"), None));
    }
    if err.kind() == io::ErrorKind::PermissionDenied || os == Some(WSAEACCES) {
        return Some((t("diagnostics.permission"), None));
    }
    if err.kind() == io::ErrorKind::AddrNotAvailable || os == Some(WSAEADDRNOTAVAIL) || os == Some(WSAEFAULT) {
        return Some((
            t("diagnostics.bad_address"),
            Some("https://github.com/Flowseal/tg-ws-proxy/issues/903#issuecomment-4726752103"),
        ));
    }
    None
}

pub fn has_ipv6() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{set_language, Lang};

    fn form(cfg: &AppConfig) -> FormValues {
        FormValues::from_config(cfg)
    }

    fn defaults() -> AppConfig {
        let mut cfg = AppConfig::default();
        cfg.secret = "00112233445566778899aabbccddeeff".into();
        cfg.language = "en".into();
        cfg
    }

    #[test]
    fn config_roundtrip_preserves_unknown_keys_and_values() {
        let mut cfg = defaults();
        cfg.extra.insert("custom".into(), json!({"a": 1}));
        cfg.cfproxy_user_domain = vec!["a.example.com".into()];
        let value = cfg.to_value();
        let back = AppConfig::from_value(&value);
        assert_eq!(back, cfg);
        assert_eq!(value["custom"]["a"], 1);
    }

    #[test]
    fn load_is_lenient_about_types_and_missing_keys() {
        let value = json!({
            "port": "nope", "pool_size": 8, "cfproxy_user_domain": "a.example.com, b.example.com",
            "dc_ip": "not-a-list", "h2": "yes", "log_max_mb": 7
        });
        let cfg = AppConfig::from_value(&value);
        assert_eq!(cfg.port, 1443);
        assert_eq!(cfg.pool_size, 8);
        assert_eq!(cfg.cfproxy_user_domain, vec!["a.example.com", "b.example.com"]);
        assert!(cfg.cfproxy_user_domain_enabled);
        assert_eq!(cfg.dc_ip.len(), 2);
        assert!(cfg.h2);
        assert_eq!(cfg.log_max_mb, 7.0);
        assert!(!cfg.cfproxy_worker_enabled);
    }

    #[test]
    fn out_of_range_port_falls_back_to_default() {
        assert_eq!(AppConfig::from_value(&json!({"port": 70000})).port, 1443);
        assert_eq!(AppConfig::from_value(&json!({"port": 0})).port, 1443);
        assert_eq!(AppConfig::from_value(&json!({"port": 8080})).port, 8080);
    }

    #[test]
    fn non_object_config_yields_defaults() {
        assert_eq!(AppConfig::from_value(&json!([1, 2])).port, 1443);
    }

    #[test]
    fn save_and_load_through_disk() {
        let dir = std::env::temp_dir().join(format!("tgws-cfg-{}", std::process::id()));
        let path = dir.join("nested").join("config.json");
        let mut cfg = defaults();
        cfg.port = 2000;
        cfg.save(&path).unwrap();
        assert_eq!(AppConfig::load(&path).port, 2000);
        std::fs::write(&path, "{broken").unwrap();
        assert_eq!(AppConfig::load(&path).port, 1443);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_config_applies_enable_flags_and_limits() {
        let mut cfg = defaults();
        cfg.cfproxy_user_domain = vec!["a.example.com".into()];
        cfg.cfproxy_worker_domain = vec!["w.example.com".into()];
        cfg.buf_kb = 1;
        cfg.pool_size = -5;
        let proxy = cfg.to_proxy_config().unwrap();
        assert!(proxy.cfproxy_user_domains.is_empty() && proxy.cfproxy_worker_domains.is_empty());
        assert_eq!(proxy.buffer_size, 4096);
        assert_eq!(proxy.pool_size, 0);
        cfg.cfproxy_user_domain_enabled = true;
        cfg.cfproxy_worker_enabled = true;
        let proxy = cfg.to_proxy_config().unwrap();
        assert_eq!(proxy.cfproxy_user_domains, vec!["a.example.com"]);
        assert_eq!(proxy.cfproxy_worker_domains, vec!["w.example.com"]);
        cfg.dc_ip = vec!["bad".into()];
        assert!(cfg.to_proxy_config().is_err());
    }

    #[test]
    fn telegram_link_uses_dd_secret() {
        let cfg = defaults();
        assert_eq!(
            cfg.tg_proxy_url(),
            "tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff"
        );
    }

    #[test]
    fn inet_aton_matches_libc_semantics() {
        for good in ["127.0.0.1", "0.0.0.0", "1", "127.1", "0x7f.1", "0177.0.0.1", "4294967295"] {
            assert!(inet_aton(good).is_some(), "{good}");
        }
        assert_eq!(inet_aton("127.1"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(inet_aton("0x7f.1"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        for bad in ["", "localhost", "256.1.1.1", "1.2.3.4.5", "1..2", "a.b.c.d", "4294967296", "1.2.3.256", "::1"] {
            assert!(inet_aton(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn validation_accepts_good_form_and_normalizes() {
        set_language(Lang::En);
        let cfg = defaults();
        let mut values = form(&cfg);
        values.host = " 127.0.0.1 ".into();
        values.port = " 8443 ".into();
        values.dc_ip = "2:149.154.167.220\n\n 4:1.2.3.4 ".into();
        values.cfproxy_user_domain = "A.example.com, a.example.com".into();
        values.buf_kb = "512.9".into();
        values.pool_size = "x".into();
        values.log_max_mb = "2.5".into();
        let out = validate_settings(&values, &cfg, &defaults()).unwrap();
        assert_eq!(out.port, 8443);
        assert_eq!(out.dc_ip, vec!["2:149.154.167.220", "4:1.2.3.4"]);
        assert_eq!(out.cfproxy_user_domain, vec!["A.example.com"]);
        assert_eq!(out.buf_kb, 512);
        assert_eq!(out.pool_size, defaults().pool_size);
        assert_eq!(out.log_max_mb, 2.5);
    }

    #[test]
    fn validation_reports_each_error_class() {
        set_language(Lang::En);
        let cfg = defaults();
        let check = |edit: &dyn Fn(&mut FormValues)| {
            let mut values = form(&cfg);
            edit(&mut values);
            validate_settings(&values, &cfg, &defaults()).unwrap_err()
        };
        assert_eq!(check(&|v| v.host = "localhost".into()), t("validation.bad_host"));
        assert_eq!(check(&|v| v.port = "0".into()), t("validation.bad_port"));
        assert_eq!(check(&|v| v.port = "abc".into()), t("validation.bad_port"));
        assert_eq!(check(&|v| v.port = "65536".into()), t("validation.bad_port"));
        assert_eq!(check(&|v| v.secret = "abc".into()), t("validation.bad_secret_len"));
        assert_eq!(check(&|v| v.secret = "z".repeat(32)), t("validation.bad_secret_hex"));
        assert_eq!(
            check(&|v| v.dc_ip = "2-1.2.3.4".into()),
            tf("validation.dc_format", &[("entry", "2-1.2.3.4")])
        );
        assert_eq!(
            check(&|v| v.dc_ip = "2:1.2".into()),
            tf("validation.dc_invalid", &[("entry", "2:1.2")])
        );
    }

    #[test]
    fn ui_only_changes_do_not_require_restart() {
        let base = defaults();
        let mut changed = base.clone();
        changed.appearance = "dark".into();
        changed.language = "ru".into();
        changed.autostart = true;
        let keys = base.changed_keys(&changed);
        assert_eq!(keys.len(), 3);
        assert!(!requires_restart(&keys));
        changed.port = 9999;
        assert!(requires_restart(&base.changed_keys(&changed)));
        assert!(base.changed_keys(&base).is_empty());
    }

    #[test]
    fn listen_errors_are_diagnosed() {
        set_language(Lang::En);
        let busy = io::Error::from(io::ErrorKind::AddrInUse);
        assert_eq!(diagnose_listen_error(&busy).unwrap().0, t("diagnostics.port_busy"));
        let denied = io::Error::from_raw_os_error(10013);
        assert_eq!(diagnose_listen_error(&denied).unwrap().0, t("diagnostics.permission"));
        let bad = io::Error::from(io::ErrorKind::AddrNotAvailable);
        let (msg, link) = diagnose_listen_error(&bad).unwrap();
        assert_eq!(msg, t("diagnostics.bad_address"));
        assert!(link.is_some());
        assert!(diagnose_listen_error(&io::Error::from(io::ErrorKind::Other)).is_none());
    }

    #[test]
    fn number_formatting() {
        assert_eq!(format_number(5.0), "5");
        assert_eq!(format_number(2.5), "2.5");
    }

    #[test]
    fn paths_derive_from_directory() {
        let paths = AppPaths::new(PathBuf::from("/tmp/x"));
        assert!(paths.config.ends_with("config.json"));
        assert!(paths.log.ends_with("proxy.log"));
    }
}

#[cfg(test)]
mod field_tests {
    use super::*;
    use crate::i18n::{set_language, Lang};

    fn base_form() -> FormValues {
        let mut cfg = AppConfig::default();
        cfg.secret = "00112233445566778899aabbccddeeff".into();
        FormValues::from_config(&cfg)
    }

    #[test]
    fn valid_form_has_no_field_errors_and_yields_link() {
        set_language(Lang::En);
        let form = base_form();
        assert!(!field_errors(&form).any());
        assert_eq!(
            link_from_form(&form).unwrap(),
            "tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff"
        );
    }

    #[test]
    fn every_field_reports_independently() {
        set_language(Lang::En);
        let mut form = base_form();
        form.host = "nope".into();
        form.port = "99999".into();
        form.dc_ip = "2:1.2".into();
        form.secret = "xyz".into();
        let errors = field_errors(&form);
        assert!(errors.host.is_some() && errors.port.is_some() && errors.dc.is_some() && errors.secret.is_some());
        assert_eq!(errors.first(), errors.host.as_ref());
        assert!(link_from_form(&form).is_none());
    }

    #[test]
    fn dc_error_does_not_block_the_link() {
        set_language(Lang::En);
        let mut form = base_form();
        form.dc_ip = "bad".into();
        assert!(field_errors(&form).dc.is_some());
        assert!(link_from_form(&form).is_some());
    }

    #[test]
    fn form_equality_detects_edits() {
        let form = base_form();
        let mut other = form.clone();
        assert_eq!(form, other);
        other.verbose = true;
        assert_ne!(form, other);
    }
}
