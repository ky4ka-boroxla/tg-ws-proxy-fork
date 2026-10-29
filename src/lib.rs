pub mod app_config;
pub mod balancer;
pub mod bridge;
pub mod cli;
pub mod cf_h2;
pub mod config;
pub mod connectivity;
pub mod crypto;
pub mod fake_tls;
pub mod i18n;
pub mod logging;
pub mod net;
pub mod pool;
pub mod proxy;
pub mod qr;
pub mod stats;
pub mod update_check;
pub mod utils;
pub mod ws;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(windows)]
pub mod win;
