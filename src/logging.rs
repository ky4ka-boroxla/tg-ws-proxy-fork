use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use log::{Level, LevelFilter, Log, Metadata, Record};
use parking_lot::Mutex;

use crate::utils::censor_domains;

const MIN_BYTES: u64 = 32 * 1024;
const MIN_BACKUPS: u32 = 1;

pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    backups: u32,
    file: Option<File>,
    size: u64,
}

impl RotatingFile {
    pub fn new(path: impl Into<PathBuf>, log_max_mb: f64, backups: u32) -> io::Result<Self> {
        let path = path.into();
        let max_bytes = MIN_BYTES.max((log_max_mb * 1024.0 * 1024.0) as u64);
        let backups = backups.max(MIN_BACKUPS);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self { path, max_bytes, backups, file: Some(file), size })
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    fn backup_path(&self, index: u32) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }

    fn rollover(&mut self) -> io::Result<()> {
        self.file = None;
        for index in (1..self.backups).rev() {
            let source = self.backup_path(index);
            let target = self.backup_path(index + 1);
            if source.exists() {
                let _ = fs::remove_file(&target);
                let _ = fs::rename(&source, &target);
            }
        }
        let first = self.backup_path(1);
        let _ = fs::remove_file(&first);
        let _ = fs::rename(&self.path, &first);
        self.file = Some(OpenOptions::new().create(true).append(true).open(&self.path)?);
        self.size = 0;
        Ok(())
    }

    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        let bytes = line.len() as u64 + 1;
        if self.size > 0 && self.size + bytes >= self.max_bytes {
            self.rollover()?;
        }
        if self.file.is_none() {
            self.file = Some(OpenOptions::new().create(true).append(true).open(&self.path)?);
        }
        if let Some(file) = self.file.as_mut() {
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
            self.size += bytes;
        }
        Ok(())
    }
}

pub struct LogOptions {
    pub verbose: bool,
    pub file: Option<PathBuf>,
    pub max_mb: f64,
    pub backups: u32,
    pub console: bool,
}

impl Default for LogOptions {
    fn default() -> Self {
        Self { verbose: false, file: None, max_mb: 5.0, backups: 1, console: true }
    }
}

struct Logger {
    console: bool,
    file: Option<Mutex<RotatingFile>>,
    level: LevelFilter,
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::Error => "ERROR",
        Level::Warn => "WARNING",
        Level::Info => "INFO",
        Level::Debug | Level::Trace => "DEBUG",
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level && !is_noisy(metadata.target())
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let message = censor_domains(&record.args().to_string());
        let now = chrono::Local::now();
        let level = level_name(record.level());
        if self.console {
            let _ = writeln!(
                io::stderr(),
                "{}  {:<5}  {}",
                now.format("%H:%M:%S"),
                level,
                message
            );
        }
        if let Some(file) = &self.file {
            let line = format!(
                "{}  {:<5}  {}  {}",
                now.format("%Y-%m-%d %H:%M:%S"),
                level,
                display_target(record.target()),
                message
            );
            let _ = file.lock().write_line(&line);
        }
    }

    fn flush(&self) {}
}

fn is_noisy(target: &str) -> bool {
    ["h2", "hyper", "rustls", "tokio_rustls", "tokio", "mio", "want"]
        .iter()
        .any(|prefix| target == *prefix || target.starts_with(&format!("{prefix}::")))
}

fn display_target(target: &str) -> &'static str {
    if target.contains("tray") || target.contains("app") {
        "tg-ws-tray"
    } else {
        "tg-mtproto-proxy"
    }
}

static INIT: OnceLock<()> = OnceLock::new();

pub fn init(options: LogOptions) -> io::Result<()> {
    let file = match &options.file {
        Some(path) => Some(Mutex::new(RotatingFile::new(path, options.max_mb, options.backups)?)),
        None => None,
    };
    let level = if options.verbose { LevelFilter::Debug } else { LevelFilter::Info };
    if INIT.set(()).is_err() {
        return Ok(());
    }
    let logger = Logger { console: options.console, file, level };
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(level);
    }
    Ok(())
}

pub fn remove_if_exists(path: &Path) {
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tgwsproxy-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tiny_limit_is_floored_and_zero_backups_still_rotate() {
        let dir = temp_dir("rot");
        let path = dir.join("proxy.log");
        let mut file = RotatingFile::new(&path, 0.0001, 0).unwrap();
        assert_eq!(file.max_bytes(), MIN_BYTES);
        let line = "x".repeat(1000);
        for _ in 0..80 {
            file.write_line(&line).unwrap();
        }
        assert!(dir.join("proxy.log.1").exists());
        assert!(fs::metadata(&path).unwrap().len() < MIN_BYTES);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiple_backups_shift_in_order() {
        let dir = temp_dir("shift");
        let path = dir.join("proxy.log");
        let mut file = RotatingFile::new(&path, 0.0001, 2).unwrap();
        let line = "y".repeat(1000);
        for _ in 0..200 {
            file.write_line(&line).unwrap();
        }
        assert!(dir.join("proxy.log.1").exists());
        assert!(dir.join("proxy.log.2").exists());
        assert!(!dir.join("proxy.log.3").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn noisy_crates_are_filtered() {
        assert!(is_noisy("h2::codec"));
        assert!(is_noisy("tokio"));
        assert!(!is_noisy("tg_ws_proxy::proxy"));
    }
}
