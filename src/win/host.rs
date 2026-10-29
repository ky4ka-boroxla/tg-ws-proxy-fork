use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::app_config::{diagnose_listen_error, AppConfig};
use crate::i18n::t;
use crate::proxy;

type ErrorSink = Arc<dyn Fn(String, Option<&'static str>) + Send + Sync>;

struct Running {
    stop: CancellationToken,
    thread: JoinHandle<()>,
}

#[derive(Default)]
pub struct ProxyHost {
    running: Mutex<Option<Running>>,
}

impl ProxyHost {
    pub fn start(&self, config: &AppConfig, on_error: ErrorSink) {
        let mut running = self.running.lock();
        if let Some(existing) = running.as_ref() {
            if !existing.thread.is_finished() {
                log::info!("Proxy already running");
                return;
            }
        }
        let proxy_config = match config.to_proxy_config() {
            Ok(cfg) => Arc::new(cfg),
            Err(err) => {
                log::error!("Bad config dc_ip: {err}");
                on_error(t("error.dc_config"), None);
                return;
            }
        };
        log::info!("Starting proxy on {}:{} ...", proxy_config.host, proxy_config.port);
        let stop = CancellationToken::new();
        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("proxy".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        log::error!("Cannot start runtime: {err}");
                        return;
                    }
                };
                let result = runtime.block_on(proxy::run(proxy_config, thread_stop));
                if let Err(err) = result {
                    log::error!("Proxy thread crashed: {err:?}");
                    if let Some((message, link)) = diagnose_listen_error(&err) {
                        on_error(message, link);
                    }
                }
                runtime.shutdown_timeout(Duration::from_secs(2));
            })
            .expect("spawn proxy thread");
        *running = Some(Running { stop, thread });
    }

    pub fn stop(&self) {
        let running = self.running.lock().take();
        if let Some(running) = running {
            running.stop.cancel();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !running.thread.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if running.thread.is_finished() {
                let _ = running.thread.join();
            } else {
                log::warn!("Proxy thread did not stop within timeout; port may still be in use");
            }
        }
        log::info!("Proxy stopped");
    }

    pub fn restart(&self, config: &AppConfig, on_error: ErrorSink) {
        log::info!("Restarting proxy...");
        self.stop();
        std::thread::sleep(Duration::from_secs(1));
        self.start(config, on_error);
    }
}
