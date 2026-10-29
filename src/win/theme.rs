use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;

pub fn system_prefers_dark() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", KEY_READ)
        .and_then(|key| key.get_value::<u32, _>("AppsUseLightTheme"))
        .map(|value| value == 0)
        .unwrap_or(false)
}

pub fn is_dark(appearance: &str) -> bool {
    match appearance {
        "dark" => true,
        "light" => false,
        _ => system_prefers_dark(),
    }
}

pub const ACCENTS: [&str; 6] = ["telegram", "violet", "emerald", "sunset", "rose", "cyan"];

pub fn accent_index(name: &str) -> i32 {
    ACCENTS.iter().position(|a| *a == name).unwrap_or(0) as i32
}

pub fn accent_name(index: i32) -> &'static str {
    ACCENTS[index.clamp(0, ACCENTS.len() as i32 - 1) as usize]
}
