use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;

use crate::app_config::{exe_path, APP_NAME};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

fn command() -> String {
    format!("\"{}\"", exe_path().display())
}

pub fn is_enabled() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey_with_flags(RUN_KEY, KEY_READ) {
        Ok(key) => key
            .get_value::<String, _>(APP_NAME)
            .map(|value| value.trim() == command().trim())
            .unwrap_or(false),
        Err(_) => false,
    }
}

pub fn set_enabled(enabled: bool) -> std::io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(RUN_KEY)?;
    if enabled {
        key.set_value(APP_NAME, &command())
    } else {
        match key.delete_value(APP_NAME) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}
