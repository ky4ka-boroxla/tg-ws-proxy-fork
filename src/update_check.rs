use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use crate::net::https_get;

pub const REPO: &str = "ky4ka-boroxla/tg-ws-proxy-fork";
pub const RELEASES_PAGE_URL: &str = "https://github.com/ky4ka-boroxla/tg-ws-proxy-fork/releases/latest";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateStatus {
    pub checked: bool,
    pub has_update: bool,
    pub ahead_of_release: bool,
    pub latest: Option<String>,
    pub html_url: String,
    pub error: Option<String>,
    pub assets: Vec<Asset>,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            checked: false,
            has_update: false,
            ahead_of_release: false,
            latest: None,
            html_url: RELEASES_PAGE_URL.to_string(),
            error: None,
            assets: Vec::new(),
        }
    }
}

static STATE: Mutex<Option<UpdateStatus>> = Mutex::new(None);

pub fn parse_version(text: &str) -> Vec<u64> {
    text.trim()
        .trim_start_matches(['v', 'V'])
        .split('.')
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().unwrap_or(0)
        })
        .collect()
}

pub fn version_gt(a: &str, b: &str) -> bool {
    let (a, b) = (parse_version(a), parse_version(b));
    for index in 0..a.len().max(b.len()) {
        let x = a.get(index).copied().unwrap_or(0);
        let y = b.get(index).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

fn extract_assets(data: &Value) -> Result<Vec<Asset>, String> {
    let assets = match data.get("assets") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err("Invalid release assets from GitHub".to_string()),
    };
    Ok(assets
        .iter()
        .filter_map(|asset| {
            let name = asset.get("name")?.as_str().filter(|s| !s.is_empty())?;
            let url = asset.get("browser_download_url")?.as_str().filter(|s| !s.is_empty())?;
            let digest = asset.get("digest").and_then(Value::as_str).unwrap_or("");
            Some(Asset { name: name.to_string(), url: url.to_string(), digest: digest.to_string() })
        })
        .collect())
}

pub fn evaluate_release(data: &Value, current_version: &str) -> UpdateStatus {
    let mut status = UpdateStatus { checked: true, ..Default::default() };
    let result = (|| -> Result<(), String> {
        let tag = data
            .get("tag_name")
            .and_then(Value::as_str)
            .ok_or_else(|| "Invalid release from GitHub".to_string())?;
        let latest = tag.trim().trim_start_matches(['v', 'V']).to_string();
        if !latest.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return Err("Invalid release version from GitHub".to_string());
        }
        status.has_update = version_gt(&latest, current_version);
        status.ahead_of_release = version_gt(current_version, &latest);
        status.html_url = data
            .get("html_url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(RELEASES_PAGE_URL)
            .to_string();
        status.assets = extract_assets(data)?;
        status.latest = Some(latest);
        Ok(())
    })();
    if let Err(message) = result {
        status = UpdateStatus { checked: true, error: Some(message), ..Default::default() };
    }
    status
}

pub async fn fetch_latest_release(timeout: Duration) -> Result<Value, String> {
    let response = https_get(
        "api.github.com",
        &format!("/repos/{REPO}/releases/latest"),
        &[("Accept", "application/vnd.github+json"), ("User-Agent", "tg-ws-proxy-update-check")],
        timeout,
    )
    .await
    .map_err(|e| e.to_string())?;
    if response.status != 200 {
        return Err(format!("HTTP {}", response.status));
    }
    serde_json::from_slice(&response.body).map_err(|e| e.to_string())
}

pub async fn run_check(current_version: &str) {
    let status = match fetch_latest_release(Duration::from_secs(12)).await {
        Ok(data) => evaluate_release(&data, current_version),
        Err(message) => {
            log::warn!("Update check failed: {message}");
            UpdateStatus { checked: true, error: Some(message), ..Default::default() }
        }
    };
    if let Ok(mut state) = STATE.lock() {
        *state = Some(status);
    }
}

pub fn get_status() -> UpdateStatus {
    STATE.lock().ok().and_then(|s| s.clone()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn version_parsing_and_ordering() {
        assert_eq!(parse_version("v1.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_version("1.2.3-beta"), vec![1, 2, 3]);
        assert_eq!(parse_version("1.x"), vec![1, 0]);
        assert!(version_gt("1.10.0", "1.9.9"));
        assert!(version_gt("2", "1.99"));
        assert!(!version_gt("1.2", "1.2.0"));
        assert!(!version_gt("1.2.0", "1.2"));
        assert!(version_gt("1.2.1", "1.2"));
    }

    #[test]
    fn newer_release_is_reported_with_assets() {
        let data = json!({
            "tag_name": "v1.12.0",
            "html_url": "https://example.test/r",
            "assets": [
                {"name": "TgWsProxy.exe", "browser_download_url": "https://example.test/a", "digest": "sha256:abc"},
                {"name": "", "browser_download_url": "https://example.test/b"},
                {"name": "x", "browser_download_url": ""},
                "junk"
            ]
        });
        let status = evaluate_release(&data, "1.11.2");
        assert!(status.checked && status.has_update && !status.ahead_of_release);
        assert_eq!(status.latest.as_deref(), Some("1.12.0"));
        assert_eq!(status.html_url, "https://example.test/r");
        assert_eq!(status.assets.len(), 1);
        assert_eq!(status.assets[0].digest, "sha256:abc");
    }

    #[test]
    fn current_ahead_of_release_is_flagged() {
        let status = evaluate_release(&json!({"tag_name": "1.0.0"}), "1.1.0");
        assert!(status.ahead_of_release && !status.has_update);
        assert_eq!(status.html_url, RELEASES_PAGE_URL);
    }

    #[test]
    fn same_version_is_up_to_date() {
        let status = evaluate_release(&json!({"tag_name": "v1.11.2"}), "1.11.2");
        assert!(!status.has_update && !status.ahead_of_release && status.error.is_none());
    }

    #[test]
    fn invalid_payloads_become_errors() {
        for data in [json!({}), json!({"tag_name": 5}), json!({"tag_name": "latest"}), json!({"tag_name": "1.0", "assets": "x"})] {
            let status = evaluate_release(&data, "1.0");
            assert!(status.checked && status.error.is_some());
            assert!(!status.has_update && status.latest.is_none() && status.assets.is_empty());
        }
    }

    #[test]
    fn status_defaults_before_any_check() {
        let status = UpdateStatus::default();
        assert!(!status.checked);
    }
}
