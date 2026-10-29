use clap::Parser;

use crate::config::{coerce_domain_text, parse_dc_ip_list, random_secret, ProxyConfig};

#[derive(Parser, Debug, Clone)]
#[command(name = "tg-ws-proxy-cli", version, about = "Telegram MTProto WebSocket Bridge Proxy")]
pub struct Args {
    #[arg(long, default_value_t = 1443, help = "Listen port (default 1443)")]
    pub port: u16,

    #[arg(long, default_value = "127.0.0.1", help = "Listen host (default 127.0.0.1)")]
    pub host: String,

    #[arg(long, help = "MTProto proxy secret (32 hex chars). Auto-generated if not provided.")]
    pub secret: Option<String>,

    #[arg(
        long = "dc-ip",
        value_name = "DC:IP",
        num_args = 0..=1,
        default_missing_value = "",
        help = "Target IP for a DC, e.g. --dc-ip 2:149.154.167.220"
    )]
    pub dc_ip: Option<Vec<String>>,

    #[arg(short, long, help = "Debug logging")]
    pub verbose: bool,

    #[arg(long, value_name = "PATH", help = "Log to file with rotation (default: stderr only)")]
    pub log_file: Option<String>,

    #[arg(long, value_name = "MB", default_value_t = 5.0, help = "Max log file size in MB before rotation (default 5)")]
    pub log_max_mb: f64,

    #[arg(long, value_name = "N", default_value_t = 1, help = "Number of rotated log files to keep (min 1)")]
    pub log_backups: u32,

    #[arg(long, allow_negative_numbers = true, value_name = "KB", default_value_t = 256, help = "Socket send/recv buffer size in KB (default 256)")]
    pub buf_kb: i64,

    #[arg(long, allow_negative_numbers = true, value_name = "N", default_value_t = 4, help = "WS connection pool size per DC (default 4, 0 disables direct WS)")]
    pub pool_size: i64,

    #[arg(long, value_name = "DOMAIN", help = "User defined Cloudflare-proxied domain (repeatable)")]
    pub cfproxy_domain: Vec<String>,

    #[arg(long, value_name = "DOMAIN", help = "Cloudflare Worker domain for WS fallback (repeatable)")]
    pub cfproxy_worker_domain: Vec<String>,

    #[arg(long, conflicts_with = "cfproxy_h2_media", help = "Disable HTTP/2 multiplexing for CF media (enabled by default)")]
    pub no_h2: bool,

    #[arg(long, hide = true)]
    pub cfproxy_h2_media: bool,

    #[arg(long, help = "Disable Cloudflare proxy fallback")]
    pub no_cfproxy: bool,

    #[arg(long, help = "Use 80 port for CF-proxy and CF-worker connections")]
    pub no_secure: bool,

    #[arg(long, value_name = "DOMAIN", default_value = "", help = "Enable Fake TLS (ee-secret) masking with the given SNI domain")]
    pub fake_tls_domain: String,

    #[arg(long, help = "Force ALL traffic to Telegram TEST datacenters")]
    pub force_test_dc: bool,

    #[arg(long, help = "Accept PROXY protocol v1 header (for use behind nginx/haproxy)")]
    pub proxy_protocol: bool,
}

pub fn build_config(args: &Args) -> Result<ProxyConfig, String> {
    let dc_list: Vec<String> = match &args.dc_ip {
        None => vec!["2:149.154.167.220".to_string(), "4:149.154.167.220".to_string()],
        Some(list) if list.iter().any(|entry| entry.is_empty()) => Vec::new(),
        Some(list) => list.clone(),
    };
    let dc_redirects = parse_dc_ip_list(&dc_list).map_err(|e| e.to_string())?;

    let secret = match &args.secret {
        Some(secret) => {
            let secret = secret.trim().to_string();
            if secret.len() != 32 {
                return Err("Secret must be exactly 32 hex characters".to_string());
            }
            if hex::decode(&secret).is_err() {
                return Err("Secret must be valid hex".to_string());
            }
            secret
        }
        None => {
            let secret = random_secret();
            log::info!("Generated secret: {secret}");
            secret
        }
    };

    Ok(ProxyConfig {
        port: args.port,
        host: args.host.clone(),
        secret,
        dc_redirects,
        buffer_size: (args.buf_kb.max(4) as usize) * 1024,
        pool_size: args.pool_size.max(0) as usize,
        fallback_cfproxy: !args.no_cfproxy,
        cfproxy_user_domains: coerce_domain_text(&args.cfproxy_domain.join(" ")),
        cfproxy_worker_domains: coerce_domain_text(&args.cfproxy_worker_domain.join(" ")),
        cfproxy_h2_media: !args.no_h2,
        disable_secure: args.no_secure,
        fake_tls_domain: args.fake_tls_domain.trim().to_string(),
        proxy_protocol: args.proxy_protocol,
        force_test_dc: args.force_test_dc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        let mut full = vec!["tg-ws-proxy-cli"];
        full.extend_from_slice(args);
        Args::try_parse_from(full)
    }

    #[test]
    fn defaults_match_the_python_cli() {
        let cfg = build_config(&parse(&[]).unwrap()).unwrap();
        assert_eq!(cfg.port, 1443);
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.buffer_size, 256 * 1024);
        assert_eq!(cfg.pool_size, 4);
        assert!(cfg.fallback_cfproxy && cfg.cfproxy_h2_media);
        assert_eq!(cfg.dc_redirects.len(), 2);
        assert_eq!(cfg.dc_redirects[&2], "149.154.167.220");
        assert_eq!(cfg.secret.len(), 32);
    }

    #[test]
    fn bare_dc_ip_clears_the_default_list() {
        let cfg = build_config(&parse(&["--dc-ip"]).unwrap()).unwrap();
        assert!(cfg.dc_redirects.is_empty());
    }

    #[test]
    fn dc_ip_is_repeatable() {
        let cfg = build_config(&parse(&["--dc-ip", "1:1.1.1.1", "--dc-ip", "3:3.3.3.3"]).unwrap()).unwrap();
        assert_eq!(cfg.dc_redirects.len(), 2);
        assert_eq!(cfg.dc_redirects[&3], "3.3.3.3");
    }

    #[test]
    fn invalid_values_are_reported() {
        assert!(build_config(&parse(&["--dc-ip", "bad"]).unwrap()).is_err());
        assert!(build_config(&parse(&["--secret", "abc"]).unwrap()).is_err());
        assert!(build_config(&parse(&["--secret", &"z".repeat(32)]).unwrap()).is_err());
    }

    #[test]
    fn flags_map_onto_config() {
        let cfg = build_config(
            &parse(&[
                "--no-h2", "--no-cfproxy", "--no-secure", "--force-test-dc", "--proxy-protocol",
                "--pool-size", "-3", "--buf-kb", "1", "--fake-tls-domain", " example.com ",
                "--cfproxy-domain", "a.com, b.com", "--cfproxy-domain", "A.com",
                "--cfproxy-worker-domain", "w.example.com",
            ])
            .unwrap(),
        )
        .unwrap();
        assert!(!cfg.cfproxy_h2_media && !cfg.fallback_cfproxy && cfg.disable_secure);
        assert!(cfg.force_test_dc && cfg.proxy_protocol);
        assert_eq!(cfg.pool_size, 0);
        assert_eq!(cfg.buffer_size, 4096);
        assert_eq!(cfg.fake_tls_domain, "example.com");
        assert_eq!(cfg.cfproxy_user_domains, vec!["a.com", "b.com"]);
        assert_eq!(cfg.cfproxy_worker_domains, vec!["w.example.com"]);
        assert!(!cfg.h2_enabled());
    }

    #[test]
    fn help_advertises_opt_out_only() {
        let mut help = Vec::new();
        <Args as clap::CommandFactory>::command().write_long_help(&mut help).unwrap();
        let text = String::from_utf8(help).unwrap();
        assert!(text.contains("--no-h2"));
        assert!(!text.contains("--cfproxy-h2-media"));
    }

    #[test]
    fn h2_flags_are_mutually_exclusive() {
        assert!(parse(&["--no-h2", "--cfproxy-h2-media"]).is_err());
    }
}
