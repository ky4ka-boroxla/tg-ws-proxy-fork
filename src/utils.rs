use std::net::UdpSocket;
use std::sync::OnceLock;

use fancy_regex::{Captures, Regex};

pub const ZERO_64: [u8; 64] = [0u8; 64];
pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8;
pub const PREKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

pub const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef; 4];
pub const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee; 4];
pub const PROTO_TAG_SECURE: [u8; 4] = [0xdd; 4];

pub const PROTO_ABRIDGED_INT: u32 = 0xEFEF_EFEF;
pub const PROTO_INTERMEDIATE_INT: u32 = 0xEEEE_EEEE;
pub const PROTO_PADDED_INTERMEDIATE_INT: u32 = 0xDDDD_DDDD;

pub const RESERVED_FIRST_BYTE: u8 = 0xEF;
pub const RESERVED_STARTS: [[u8; 4]; 7] = [
    [0x48, 0x45, 0x41, 0x44],
    [0x50, 0x4F, 0x53, 0x54],
    [0x47, 0x45, 0x54, 0x20],
    [0xee, 0xee, 0xee, 0xee],
    [0xdd, 0xdd, 0xdd, 0xdd],
    [0x16, 0x03, 0x01, 0x02],
    [0x4F, 0x50, 0x54, 0x49],
];
pub const RESERVED_CONTINUE: [u8; 4] = [0, 0, 0, 0];

pub const GITHUB_PINNED_IPS: [(&str, &str); 2] = [
    ("release-assets.githubusercontent.com", "185.199.109.133"),
    ("raw.githubusercontent.com", "185.199.109.133"),
];

pub const DC_DEFAULT_IPS: [(i32, &str); 6] = [
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
    (203, "91.105.192.100"),
];

pub const DC_TEST_IPS: [(i32, &str); 3] = [
    (1, "149.154.175.10"),
    (2, "149.154.167.40"),
    (3, "149.154.175.117"),
];

pub const WS_PATH: &str = "/apiws";
pub const WS_PATH_TEST: &str = "/apiws_test";

pub fn dc_default_ip(dc: i32) -> Option<&'static str> {
    DC_DEFAULT_IPS.iter().find(|(d, _)| *d == dc).map(|(_, ip)| *ip)
}

pub fn dc_test_ip(dc: i32) -> Option<&'static str> {
    DC_TEST_IPS.iter().find(|(d, _)| *d == dc).map(|(_, ip)| *ip)
}

pub fn ws_domains(dc: i32, is_media: bool) -> Vec<String> {
    let dc = if dc == 203 { 2 } else { dc };
    if !is_media {
        return vec![format!("kws{dc}.web.telegram.org")];
    }
    vec![
        format!("kws{dc}-1.web.telegram.org"),
        format!("kws{dc}.web.telegram.org"),
    ]
}

pub fn human_bytes(n: u64) -> String {
    let mut value = n as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if value.abs() < 1024.0 {
            return format!("{value:.1}{unit}");
        }
        value /= 1024.0;
    }
    format!("{value:.1}TB")
}

pub fn get_link_host(host: &str) -> String {
    if host != "0.0.0.0" {
        return host.to_string();
    }
    let probe = || -> std::io::Result<String> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        Ok(socket.local_addr()?.ip().to_string())
    };
    probe().unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn domain_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?<![\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w-])",
        )
        .expect("domain pattern")
    })
}

fn censor_domain(domain: &str) -> String {
    let normalized = domain.to_lowercase();
    let normalized = normalized.trim_end_matches('.');
    if normalized == "telegram.org"
        || normalized.ends_with(".telegram.org")
        || normalized.ends_with(".log")
    {
        return domain.to_string();
    }
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return domain.to_string();
    }
    let last = parts.len() - 1;
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            if i == last {
                return (*part).to_string();
            }
            let chars: Vec<char> = part.chars().collect();
            let keep = chars.len() / 2;
            let mut out: String = chars[..keep].iter().collect();
            out.extend(std::iter::repeat('*').take(chars.len() - keep));
            out
        })
        .collect::<Vec<_>>()
        .join(".")
}

pub fn censor_domains(text: &str) -> String {
    domain_pattern()
        .replace_all(text, |caps: &Captures| censor_domain(&caps[0]))
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_scales_units() {
        assert_eq!(human_bytes(0), "0.0B");
        assert_eq!(human_bytes(1023), "1023.0B");
        assert_eq!(human_bytes(1024), "1.0KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0GB");
        assert_eq!(human_bytes(2048u64 * 1024 * 1024 * 1024), "2.0TB");
    }

    #[test]
    fn ws_domains_for_regular_and_media() {
        assert_eq!(ws_domains(2, false), vec!["kws2.web.telegram.org"]);
        assert_eq!(
            ws_domains(2, true),
            vec!["kws2-1.web.telegram.org", "kws2.web.telegram.org"]
        );
        assert_eq!(ws_domains(203, false), vec!["kws2.web.telegram.org"]);
    }

    #[test]
    fn censor_masks_domains_but_not_telegram_or_logs() {
        assert_eq!(censor_domains("connect to example.com now"), "connect to exa****.com now");
        assert_eq!(
            censor_domains("kws2.web.telegram.org"),
            "kws2.web.telegram.org"
        );
        assert_eq!(censor_domains("proxy.log"), "proxy.log");
        assert_eq!(censor_domains("149.154.167.220:443"), "149.154.167.220:443");
        assert_eq!(censor_domains("sub.example.co.uk"), "s**.exa****.c*.uk");
    }

    #[test]
    fn link_host_passthrough() {
        assert_eq!(get_link_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(get_link_host("10.1.2.3"), "10.1.2.3");
    }

    #[test]
    fn dc_tables() {
        assert_eq!(dc_default_ip(2), Some("149.154.167.51"));
        assert_eq!(dc_default_ip(9), None);
        assert_eq!(dc_test_ip(1), Some("149.154.175.10"));
    }
}
