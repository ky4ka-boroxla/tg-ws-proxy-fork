use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::balancer::Balancer;
use crate::net::https_get;

pub const CFPROXY_DOMAINS_HOST: &str = "raw.githubusercontent.com";
pub const CFPROXY_DOMAINS_PATH: &str =
    "/ky4ka-boroxla/tg-ws-proxy-fork/main/.github/cfproxy-domains.txt";
const CFPROXY_MIN_VALID_DOMAINS: usize = 3;
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

const CFPROXY_ENC: [&str; 20] = [
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
];

pub fn decode_domain(encoded: &str) -> String {
    let Some(body) = encoded.strip_suffix(".com") else {
        return encoded.to_string();
    };
    let shift = body.chars().filter(|c| c.is_alphabetic()).count() as i64;
    let decoded: String = body
        .chars()
        .map(|c| {
            if !c.is_ascii_alphabetic() {
                return c;
            }
            let base = if c > '`' { 97i64 } else { 65i64 };
            let value = (c as i64 - base - shift).rem_euclid(26) + base;
            char::from_u32(value as u32).unwrap_or(c)
        })
        .collect();
    format!("{decoded}.co.uk")
}

pub fn default_cfproxy_domains() -> Vec<String> {
    CFPROXY_ENC.iter().map(|d| decode_domain(d)).collect()
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub host: String,
    pub secret: String,
    pub dc_redirects: BTreeMap<i32, String>,
    pub buffer_size: usize,
    pub pool_size: usize,
    pub fallback_cfproxy: bool,
    pub cfproxy_user_domains: Vec<String>,
    pub cfproxy_worker_domains: Vec<String>,
    pub cfproxy_h2_media: bool,
    pub disable_secure: bool,
    pub fake_tls_domain: String,
    pub proxy_protocol: bool,
    pub force_test_dc: bool,
}

pub fn random_secret() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let mut dc_redirects = BTreeMap::new();
        dc_redirects.insert(2, "149.154.167.220".to_string());
        dc_redirects.insert(4, "149.154.167.220".to_string());
        Self {
            port: 1443,
            host: "127.0.0.1".to_string(),
            secret: random_secret(),
            dc_redirects,
            buffer_size: 256 * 1024,
            pool_size: 4,
            fallback_cfproxy: true,
            cfproxy_user_domains: Vec::new(),
            cfproxy_worker_domains: Vec::new(),
            cfproxy_h2_media: true,
            disable_secure: false,
            fake_tls_domain: String::new(),
            proxy_protocol: false,
            force_test_dc: false,
        }
    }
}

impl ProxyConfig {
    pub fn h2_enabled(&self) -> bool {
        self.cfproxy_h2_media
            && self.fallback_cfproxy
            && !self.disable_secure
            && !self.force_test_dc
    }

    pub fn secret_bytes(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.secret)
    }
}

fn split_domain_text(text: &str) -> Vec<String> {
    text.replace([',', ';'], " ")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn dedupe_domains(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for item in items {
        let item = item.trim().to_string();
        if item.is_empty() {
            continue;
        }
        if !seen.insert(item.to_lowercase()) {
            continue;
        }
        result.push(item);
    }
    result
}

pub fn coerce_domain_list(value: &Value) -> Vec<String> {
    match value {
        Value::String(text) => dedupe_domains(split_domain_text(text)),
        Value::Array(entries) => {
            let mut items = Vec::new();
            for entry in entries {
                if let Value::String(text) = entry {
                    items.extend(split_domain_text(text));
                }
            }
            dedupe_domains(items)
        }
        _ => Vec::new(),
    }
}

pub fn coerce_domain_text(text: &str) -> Vec<String> {
    dedupe_domains(split_domain_text(text))
}

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }
    let tld = labels[labels.len() - 1];
    tld.chars().count() >= 2 && tld.chars().any(|c| c.is_alphabetic())
}

pub fn normalize_domain_pool(domains: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for domain in domains {
        let item = domain.trim().to_lowercase();
        if !is_valid_domain(&item) {
            continue;
        }
        if !seen.insert(item.clone()) {
            continue;
        }
        normalized.push(item);
    }
    normalized
}

pub fn parse_domain_payload(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(decode_domain)
        .collect()
}

async fn fetch_cfproxy_domain_list() -> Vec<String> {
    let suffix: String = (0..7)
        .map(|_| {
            let letters = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            letters[rand::thread_rng().gen_range(0..letters.len())] as char
        })
        .collect();
    let path = format!("{CFPROXY_DOMAINS_PATH}?{suffix}");
    match https_get(
        CFPROXY_DOMAINS_HOST,
        &path,
        &[("User-Agent", "tg-ws-proxy")],
        Duration::from_secs(10),
    )
    .await
    {
        Ok(response) if response.status == 200 => {
            parse_domain_payload(&String::from_utf8_lossy(&response.body))
        }
        Ok(response) => {
            log::warn!("Failed to fetch CF proxy domain list: HTTP {}", response.status);
            Vec::new()
        }
        Err(err) => {
            log::warn!("Failed to fetch CF proxy domain list: {err:?}");
            Vec::new()
        }
    }
}

pub async fn refresh_cfproxy_domains(config: &ProxyConfig, balancer: &Balancer) {
    if !config.cfproxy_user_domains.is_empty() {
        return;
    }
    let fetched = fetch_cfproxy_domain_list().await;
    let pool = normalize_domain_pool(&fetched);
    if pool.len() >= CFPROXY_MIN_VALID_DOMAINS {
        balancer.update_domains_list(&pool);
        log::info!("CF proxy domain pool updated from GitHub ({} domains)", pool.len());
        return;
    }
    if !fetched.is_empty() {
        log::warn!(
            "Ignoring fetched CF proxy domains due to low-quality payload \
             (total={}, valid={}, required>={}); keeping current domain pool",
            fetched.len(),
            pool.len(),
            CFPROXY_MIN_VALID_DOMAINS
        );
    } else {
        log::warn!("CF proxy domain refresh failed or empty response; keeping current domain pool");
    }
}

pub fn spawn_cfproxy_domain_refresh(
    config: Arc<ProxyConfig>,
    balancer: Arc<Balancer>,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    balancer.update_domains_list(&default_cfproxy_domains());
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = refresh_cfproxy_domains(&config, &balancer) => {}
            }
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(REFRESH_INTERVAL) => {}
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcIpErrorKind {
    Format,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DcIpError {
    pub entry: String,
    pub kind: DcIpErrorKind,
    pub message: String,
}

pub fn parse_dc_ip_list<S: AsRef<str>>(entries: &[S]) -> Result<BTreeMap<i32, String>, DcIpError> {
    let mut redirects = BTreeMap::new();
    for entry in entries {
        let entry = entry.as_ref();
        let Some((dc_text, ip_text)) = entry.split_once(':') else {
            return Err(DcIpError {
                entry: entry.to_string(),
                kind: DcIpErrorKind::Format,
                message: format!("Invalid --dc-ip format '{entry}', expected DC:IP"),
            });
        };
        let invalid = || DcIpError {
            entry: entry.to_string(),
            kind: DcIpErrorKind::Invalid,
            message: format!("Invalid --dc-ip '{entry}'"),
        };
        let dc: i32 = dc_text.trim().parse().map_err(|_| invalid())?;
        ip_text.parse::<Ipv4Addr>().map_err(|_| invalid())?;
        redirects.insert(dc, ip_text.to_string());
    }
    Ok(redirects)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_multiple_entries() {
        let parsed = parse_dc_ip_list(&["2:149.154.167.220", "4:1.2.3.4"]).unwrap();
        assert_eq!(parsed.get(&2).unwrap(), "149.154.167.220");
        assert_eq!(parsed.get(&4).unwrap(), "1.2.3.4");
    }

    #[test]
    fn last_entry_wins_for_duplicate_dc() {
        let parsed = parse_dc_ip_list(&["2:1.1.1.1", "2:2.2.2.2"]).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[&2], "2.2.2.2");
    }

    #[test]
    fn rejects_missing_separator() {
        let err = parse_dc_ip_list(&["2-1.2.3.4"]).unwrap_err();
        assert_eq!(err.kind, DcIpErrorKind::Format);
        assert_eq!(err.entry, "2-1.2.3.4");
    }

    #[test]
    fn rejects_short_form_ipv4() {
        for entry in ["2:149.154", "2:1.2.3.4.5", "2:999.1.1.1", "2:abc"] {
            let err = parse_dc_ip_list(&[entry]).unwrap_err();
            assert_eq!(err.kind, DcIpErrorKind::Invalid, "{entry}");
        }
    }

    #[test]
    fn rejects_non_numeric_dc() {
        assert!(parse_dc_ip_list(&["x:1.2.3.4"]).is_err());
    }

    #[test]
    fn coerce_splits_on_common_separators() {
        assert_eq!(
            coerce_domain_list(&json!("a.com, b.com; c.com d.com")),
            vec!["a.com", "b.com", "c.com", "d.com"]
        );
    }

    #[test]
    fn coerce_deduplicates_case_insensitively_keeping_first() {
        assert_eq!(coerce_domain_list(&json!(["A.com", "a.com"])), vec!["A.com"]);
    }

    #[test]
    fn coerce_flattens_sequences_and_skips_non_strings() {
        assert_eq!(
            coerce_domain_list(&json!(["a.com b.com", 5, null])),
            vec!["a.com", "b.com"]
        );
    }

    #[test]
    fn coerce_returns_empty_for_unsupported_types() {
        assert!(coerce_domain_list(&Value::Null).is_empty());
        assert!(coerce_domain_list(&json!(42)).is_empty());
    }

    #[test]
    fn accepts_ordinary_domains() {
        for domain in ["example.com", "a-b.co.uk", "x.io"] {
            assert!(is_valid_domain(domain), "{domain}");
        }
    }

    #[test]
    fn rejects_malformed_domains() {
        let long_label = format!("a.{}", "b".repeat(64));
        let long_name = format!("{}.com", "a".repeat(250));
        for domain in [
            "", "nodot", ".leading.com", "trailing.com.", "-bad.com", "bad-.com", "a..com", "a.1",
            long_label.as_str(), long_name.as_str(),
        ] {
            assert!(!is_valid_domain(domain), "{domain}");
        }
    }

    #[test]
    fn normalize_lowercases_dedupes_and_drops_invalid() {
        let input: Vec<String> = ["B.com ", "b.com", "nodot", "a.com"].iter().map(|s| s.to_string()).collect();
        assert_eq!(normalize_domain_pool(&input), vec!["b.com", "a.com"]);
    }

    #[test]
    fn decoded_defaults_are_valid_and_unique() {
        let defaults = default_cfproxy_domains();
        assert!(!defaults.is_empty());
        for domain in &defaults {
            assert!(is_valid_domain(domain), "{domain}");
        }
        let unique: HashSet<&String> = defaults.iter().collect();
        assert_eq!(unique.len(), defaults.len());
    }

    #[test]
    fn decode_known_vector_matches_reference_algorithm() {
        assert_eq!(decode_domain("virkgj.com"), "pclead.co.uk");
        assert_eq!(decode_domain("VIRKGJ.com"), "PCLEAD.co.uk");
        assert_eq!(decode_domain("plain.org"), "plain.org");
    }

    #[test]
    fn payload_parser_skips_comments_and_blank_lines() {
        let parsed = parse_domain_payload("# header\n\nvirkgj.com\nvmmzovy.com\n");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().all(|d| d.ends_with(".co.uk")));
    }

    #[test]
    fn h2_requires_cf_and_tls_and_regular_dcs() {
        let mut cfg = ProxyConfig::default();
        assert!(cfg.h2_enabled());
        cfg.disable_secure = true;
        assert!(!cfg.h2_enabled());
        cfg.disable_secure = false;
        cfg.force_test_dc = true;
        assert!(!cfg.h2_enabled());
        cfg.force_test_dc = false;
        cfg.fallback_cfproxy = false;
        assert!(!cfg.h2_enabled());
    }

    #[test]
    fn default_secret_is_32_hex_chars() {
        let cfg = ProxyConfig::default();
        assert_eq!(cfg.secret.len(), 32);
        assert_eq!(cfg.secret_bytes().unwrap().len(), 16);
    }
}
