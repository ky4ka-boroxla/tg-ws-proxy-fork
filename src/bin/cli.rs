use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tg_ws_proxy::cli::{build_config, Args};
use tg_ws_proxy::logging::{self, LogOptions};
use tg_ws_proxy::{proxy, stats};
use tokio_util::sync::CancellationToken;

fn main() -> ExitCode {
    let args = Args::parse();
    let init = logging::init(LogOptions {
        verbose: args.verbose,
        file: args.log_file.as_ref().map(PathBuf::from),
        max_mb: args.log_max_mb,
        backups: args.log_backups,
        console: true,
    });
    if let Err(err) = init {
        eprintln!("Cannot open log file: {err}");
        return ExitCode::FAILURE;
    }
    let config = match build_config(&args) {
        Ok(config) => Arc::new(config),
        Err(message) => {
            log::error!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            log::error!("Cannot start runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    let stop = CancellationToken::new();
    let result = runtime.block_on(async {
        let signal_stop = stop.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            signal_stop.cancel();
        });
        proxy::run(config, stop).await
    });
    log::info!("Shutting down. Final stats: {}", stats::stats().summary());
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("{err}");
            ExitCode::FAILURE
        }
    }
}
