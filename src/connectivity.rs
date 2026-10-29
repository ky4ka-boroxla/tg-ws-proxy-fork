use std::collections::BTreeMap;
use std::time::Duration;

use crate::i18n::{t, tf};
use crate::ws::{ConnectOptions, RawWebSocket, WsError};

pub const TEST_DCS: [i32; 6] = [1, 2, 3, 4, 5, 203];
const WORKER_DST: [(i32, &str); 6] = [
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
    (203, "91.105.192.100"),
];

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Ok,
    Fail(String),
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, Outcome::Ok)
    }
}

pub type DcResults = BTreeMap<i32, Outcome>;

fn describe(err: WsError) -> String {
    match err {
        WsError::Handshake { status_line, .. } => {
            if status_line.is_empty() { t("connectivity.no_response") } else { status_line }
        }
        WsError::Timeout => t("connectivity.timeout"),
        WsError::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => t("connectivity.timeout"),
        other => {
            let text = other.to_string();
            text.chars().take(60).collect()
        }
    }
}

async fn probe(host: &str, path: &str, secure: bool) -> Outcome {
    let options = ConnectOptions { secure, ..Default::default() };
    match RawWebSocket::connect(host, host, Duration::from_secs(5), path, &options).await {
        Ok(ws) => {
            ws.close().await;
            Outcome::Ok
        }
        Err(err) => Outcome::Fail(describe(err)),
    }
}

pub async fn cfproxy_test(domain: &str, secure: bool) -> DcResults {
    let mut results = DcResults::new();
    for dc in TEST_DCS {
        let host = format!("kws{dc}.{domain}");
        results.insert(dc, probe(&host, "/apiws", secure).await);
    }
    results
}

pub async fn cfworker_test(domain: &str, secure: bool) -> DcResults {
    let mut results = DcResults::new();
    for (dc, dst) in WORKER_DST {
        let path = format!("/apiws?dst={dst}&dc={dc}&media=0");
        results.insert(dc, probe(domain, &path, secure).await);
    }
    results
}

pub async fn multi_test(domains: &[String], worker: bool, secure: bool) -> Vec<(String, DcResults)> {
    let mut out = Vec::new();
    for domain in domains {
        let results = if worker { cfworker_test(domain, secure).await } else { cfproxy_test(domain, secure).await };
        out.push((domain.clone(), results));
    }
    out
}

pub async fn cfproxy_auto_test(domains: &[String], secure: bool) -> (Option<String>, DcResults) {
    let mut merged = DcResults::new();
    let mut best = None;
    for domain in domains.iter().rev() {
        let results = cfproxy_test(domain, secure).await;
        if results.values().all(Outcome::is_ok) {
            return (Some(domain.clone()), results);
        }
        for (dc, outcome) in results {
            if outcome.is_ok() {
                merged.insert(dc, Outcome::Ok);
                best = Some(domain.clone());
            } else {
                merged.entry(dc).or_insert(outcome);
            }
        }
    }
    (best, merged)
}

fn error_lines(prefix: &str, fail: &[(i32, &Outcome)]) -> String {
    fail.iter()
        .map(|(dc, outcome)| {
            let error = match outcome {
                Outcome::Fail(message) => message.as_str(),
                Outcome::Ok => "",
            };
            tf("connectivity.error_line", &[("prefix", prefix), ("dc", &dc.to_string()), ("error", error)])
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_results(
    title_base: &str,
    results: &DcResults,
    domain: &str,
    label_prefix: &str,
    auto_mode: bool,
    unavailable_message: &str,
) -> (String, String) {
    let ok: Vec<i32> = results.iter().filter(|(_, v)| v.is_ok()).map(|(dc, _)| *dc).collect();
    let total = TEST_DCS.len();
    if auto_mode {
        if !domain.is_empty() {
            return (
                tf("connectivity.available", &[("title", title_base)]),
                tf(
                    "connectivity.auto_ok",
                    &[("title", title_base), ("ok", &ok.len().to_string()), ("total", &total.to_string())],
                ),
            );
        }
        return (tf("connectivity.unavailable", &[("title", title_base)]), unavailable_message.to_string());
    }
    let fail: Vec<(i32, &Outcome)> = results.iter().filter(|(_, v)| !v.is_ok()).map(|(dc, v)| (*dc, v)).collect();
    if ok.len() == total {
        (
            tf("connectivity.all_ok", &[("title", title_base)]),
            tf("connectivity.all_ok_domain", &[("total", &total.to_string()), ("domain", domain)]),
        )
    } else if ok.is_empty() {
        (
            tf("connectivity.unavailable", &[("title", title_base)]),
            tf("connectivity.none_ok", &[("domain", domain), ("errors", &error_lines(label_prefix, &fail))]),
        )
    } else {
        let ok_list = ok.iter().map(|dc| format!("{label_prefix}{dc}")).collect::<Vec<_>>().join(", ");
        (
            tf("connectivity.partial", &[("title", title_base)]),
            tf(
                "connectivity.partial_detail",
                &[("domain", domain), ("ok_list", &ok_list), ("fail_list", &error_lines(label_prefix, &fail))],
            ),
        )
    }
}

pub fn format_multi_results(
    title_base: &str,
    per_domain: &[(String, DcResults)],
    label_prefix: &str,
) -> (String, String) {
    let total = TEST_DCS.len();
    let mut all_ok = true;
    let mut any_ok = false;
    let mut blocks = Vec::new();
    for (domain, results) in per_domain {
        let ok: Vec<i32> = results.iter().filter(|(_, v)| v.is_ok()).map(|(dc, _)| *dc).collect();
        let fail: Vec<i32> = results.iter().filter(|(_, v)| !v.is_ok()).map(|(dc, _)| *dc).collect();
        if ok.len() == total {
            any_ok = true;
            blocks.push(tf("connectivity.multi_all_ok", &[("domain", domain), ("total", &total.to_string())]));
        } else if ok.is_empty() {
            all_ok = false;
            blocks.push(tf("connectivity.multi_fail", &[("domain", domain)]));
        } else {
            all_ok = false;
            any_ok = true;
            let join = |list: &[i32]| list.iter().map(|dc| format!("{label_prefix}{dc}")).collect::<Vec<_>>().join(", ");
            blocks.push(tf(
                "connectivity.multi_partial",
                &[("domain", domain), ("ok_list", &join(&ok)), ("fail_list", &join(&fail))],
            ));
        }
    }
    let title = if all_ok {
        tf("connectivity.all_ok", &[("title", title_base)])
    } else if any_ok {
        tf("connectivity.partial", &[("title", title_base)])
    } else {
        tf("connectivity.unavailable", &[("title", title_base)])
    };
    (title, blocks.join("\n\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{set_language, Lang};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn results(ok: &[i32]) -> DcResults {
        TEST_DCS
            .iter()
            .map(|dc| (*dc, if ok.contains(dc) { Outcome::Ok } else { Outcome::Fail("boom".into()) }))
            .collect()
    }

    #[test]
    fn single_domain_summaries() {
        set_language(Lang::En);
        let (title, body) = format_results("CF Proxy", &results(&TEST_DCS), "a.example.com", "DC", false, "");
        assert_eq!(title, "CF Proxy: all working");
        assert!(body.contains("All 6 servers reachable via a.example.com"));
        let (title, body) = format_results("CF Proxy", &results(&[]), "a.example.com", "DC", false, "");
        assert_eq!(title, "CF Proxy: unavailable");
        assert!(body.contains("  DC1: boom") && body.contains("a.example.com"));
        let (title, body) = format_results("CF Proxy", &results(&[1, 2]), "a.example.com", "DC", false, "");
        assert_eq!(title, "CF Proxy: partially working");
        assert!(body.contains("DC1, DC2") && body.contains("  DC3: boom"));
    }

    #[test]
    fn auto_mode_summaries() {
        set_language(Lang::En);
        let (title, body) = format_results("CF Proxy", &results(&[1, 2, 3]), "a.example.com", "DC", true, "");
        assert_eq!(title, "CF Proxy: available");
        assert!(body.contains("3 of 6"));
        let (title, body) = format_results("CF Proxy", &results(&[]), "", "DC", true, "nothing");
        assert_eq!(title, "CF Proxy: unavailable");
        assert_eq!(body, "nothing");
    }

    #[test]
    fn multi_domain_summaries() {
        set_language(Lang::En);
        let per_domain = vec![
            ("a.example.com".to_string(), results(&TEST_DCS)),
            ("b.example.com".to_string(), results(&[1])),
            ("c.example.com".to_string(), results(&[])),
        ];
        let (title, body) = format_multi_results("CF Worker", &per_domain, "DC");
        assert_eq!(title, "CF Worker: partially working");
        assert!(body.contains("✓ a.example.com: all 6 servers reachable"));
        assert!(body.contains("~ b.example.com: working DC1; unreachable DC2, DC3, DC4, DC5, DC203"));
        assert!(body.contains("✗ c.example.com: unavailable"));
        let (title, _) = format_multi_results("CF Worker", &per_domain[..1], "DC");
        assert_eq!(title, "CF Worker: all working");
        let (title, _) = format_multi_results("CF Worker", &per_domain[2..], "DC");
        assert_eq!(title, "CF Worker: unavailable");
    }

    #[tokio::test]
    async fn probe_distinguishes_upgrade_rejection_and_connection_failure() {
        set_language(Lang::En);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for status in ["101 Switching Protocols", "403 Forbidden"] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                stream
                    .write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let options = ConnectOptions { secure: false, port: Some(port), ..Default::default() };
        let ok = RawWebSocket::connect("127.0.0.1", "x", Duration::from_secs(2), "/apiws", &options).await;
        assert!(ok.is_ok());
        let err = RawWebSocket::connect("127.0.0.1", "x", Duration::from_secs(2), "/apiws", &options)
            .await
            .err()
            .unwrap();
        assert_eq!(describe(err), "HTTP/1.1 403 Forbidden");
        let closed = RawWebSocket::connect("127.0.0.1", "x", Duration::from_secs(1), "/apiws", &options)
            .await
            .err()
            .unwrap();
        assert!(!describe(closed).is_empty());
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReportRow {
    pub label: String,
    pub state: i32,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub title: String,
    pub state: i32,
    pub rows: Vec<ReportRow>,
}

fn outcome_row(label: String, outcome: &Outcome) -> ReportRow {
    match outcome {
        Outcome::Ok => ReportRow { label, state: 1, detail: String::new() },
        Outcome::Fail(message) => ReportRow { label, state: 3, detail: message.clone() },
    }
}

pub fn auto_report(title_base: &str, domain: Option<&str>, results: &DcResults, unavailable_message: &str) -> Report {
    let ok = results.values().filter(|v| v.is_ok()).count();
    let mut rows: Vec<ReportRow> = results.iter().map(|(dc, o)| outcome_row(format!("DC{dc}"), o)).collect();
    match domain {
        Some(_) if ok == TEST_DCS.len() => Report {
            title: tf("connectivity.all_ok", &[("title", title_base)]),
            state: 1,
            rows,
        },
        Some(_) => Report { title: tf("connectivity.available", &[("title", title_base)]), state: 2, rows },
        None => {
            rows.insert(0, ReportRow { label: String::new(), state: 3, detail: unavailable_message.to_string() });
            Report { title: tf("connectivity.unavailable", &[("title", title_base)]), state: 3, rows }
        }
    }
}

pub fn multi_report(title_base: &str, per_domain: &[(String, DcResults)], label_prefix: &str) -> Report {
    let total = TEST_DCS.len();
    let mut all_ok = true;
    let mut any_ok = false;
    let mut rows = Vec::new();
    for (domain, results) in per_domain {
        let ok: Vec<i32> = results.iter().filter(|(_, v)| v.is_ok()).map(|(dc, _)| *dc).collect();
        let fail: Vec<i32> = results.iter().filter(|(_, v)| !v.is_ok()).map(|(dc, _)| *dc).collect();
        let join = |list: &[i32]| list.iter().map(|dc| format!("{label_prefix}{dc}")).collect::<Vec<_>>().join(", ");
        if ok.len() == total {
            any_ok = true;
            rows.push(ReportRow {
                label: domain.clone(),
                state: 1,
                detail: tf("ui.report.all", &[("total", &total.to_string())]),
            });
        } else if ok.is_empty() {
            all_ok = false;
            let first_error = results
                .values()
                .find_map(|v| if let Outcome::Fail(m) = v { Some(m.clone()) } else { None })
                .unwrap_or_default();
            rows.push(ReportRow {
                label: domain.clone(),
                state: 3,
                detail: format!("{} ({first_error})", t("ui.report.none")),
            });
        } else {
            all_ok = false;
            any_ok = true;
            rows.push(ReportRow {
                label: domain.clone(),
                state: 2,
                detail: tf("ui.report.partial", &[("ok_list", &join(&ok)), ("fail_list", &join(&fail))]),
            });
        }
    }
    let (title, state) = if all_ok {
        (tf("connectivity.all_ok", &[("title", title_base)]), 1)
    } else if any_ok {
        (tf("connectivity.partial", &[("title", title_base)]), 2)
    } else {
        (tf("connectivity.unavailable", &[("title", title_base)]), 3)
    };
    Report { title, state, rows }
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use crate::i18n::{set_language, Lang};

    fn results(ok: &[i32]) -> DcResults {
        TEST_DCS
            .iter()
            .map(|dc| (*dc, if ok.contains(dc) { Outcome::Ok } else { Outcome::Fail("boom".into()) }))
            .collect()
    }

    #[test]
    fn multi_report_rows_and_overall_state() {
        set_language(Lang::En);
        let per = vec![
            ("a.example.com".to_string(), results(&TEST_DCS)),
            ("b.example.com".to_string(), results(&[1])),
            ("c.example.com".to_string(), results(&[])),
        ];
        let report = multi_report("CF Worker", &per, "DC");
        assert_eq!(report.state, 2);
        assert_eq!(report.title, "CF Worker: partially working");
        assert_eq!(report.rows.iter().map(|r| r.state).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(report.rows[0].detail, "all 6 servers reachable");
        assert!(report.rows[1].detail.contains("working DC1") && report.rows[1].detail.contains("DC203"));
        assert!(report.rows[2].detail.contains("boom"));
        assert_eq!(multi_report("X", &per[..1], "DC").state, 1);
        assert_eq!(multi_report("X", &per[2..], "DC").state, 3);
    }

    #[test]
    fn auto_report_variants() {
        set_language(Lang::En);
        let all = auto_report("CF Proxy", Some("a.example.com"), &results(&TEST_DCS), "");
        assert_eq!((all.state, all.rows.len()), (1, 6));
        let partial = auto_report("CF Proxy", Some("a.example.com"), &results(&[1, 2]), "");
        assert_eq!(partial.state, 2);
        assert_eq!(partial.rows.iter().filter(|r| r.state == 1).count(), 2);
        let none = auto_report("CF Proxy", None, &results(&[]), "nothing works");
        assert_eq!(none.state, 3);
        assert_eq!(none.rows[0].detail, "nothing works");
        assert_eq!(none.title, "CF Proxy: unavailable");
    }
}
