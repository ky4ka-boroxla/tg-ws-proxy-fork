#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    tg_ws_proxy::win::run();

    #[cfg(not(windows))]
    {
        eprintln!("TgWsProxy tray application is Windows-only; use tg-ws-proxy-cli instead.");
        std::process::exit(2);
    }
}
