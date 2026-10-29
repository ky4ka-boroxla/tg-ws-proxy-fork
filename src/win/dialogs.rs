use std::ptr::null_mut;

use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK};

use crate::i18n::t;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn show(text: &str, title: &str, flags: u32) {
    let text = wide(text);
    let title = wide(title);
    unsafe {
        MessageBoxW(null_mut(), text.as_ptr(), title.as_ptr(), flags);
    }
}

pub fn show_error(text: &str) {
    show(text, &t("app.error_title"), MB_OK | MB_ICONERROR);
}

pub fn show_info(text: &str, title: Option<&str>) {
    let default_title = t("app.name");
    show(text, title.unwrap_or(&default_title), MB_OK | MB_ICONINFORMATION);
}
