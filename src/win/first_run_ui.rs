use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use slint::{ComponentHandle, Timer, TimerMode};

use crate::app_config::{AppConfig, AppPaths};
use crate::i18n::{set_language, Lang};
use crate::utils::get_link_host;
use crate::win::theme::is_dark;
use crate::win::tr_gen;
use crate::win::theme::accent_index;
use crate::win::ui::{FirstRunWindow, Style};
use crate::win::ui_common::{qr_image, window_icon};

pub fn run() {
    let paths = AppPaths::detect();
    let _ = paths.ensure();
    let config = AppConfig::load(&paths.config);
    set_language(Lang::parse(&config.language));

    let ui = match FirstRunWindow::new() {
        Ok(ui) => ui,
        Err(err) => {
            log::error!("Cannot create first-run window: {err}");
            let _ = std::fs::write(&paths.first_run_marker, b"");
            std::process::exit(0);
        }
    };
    tr_gen::apply(&ui);
    ui.set_win_icon(window_icon());
    {
        let style = ui.global::<Style>();
        style.set_dark(is_dark(&config.appearance));
        style.set_accent_index(accent_index(&config.accent));
    }
    let url = config.tg_proxy_url();
    ui.set_host(get_link_host(&config.host).into());
    ui.set_port(config.port.to_string().into());
    ui.set_secret(config.secret.clone().into());
    ui.set_qr(qr_image(&url));

    let reset_timer = Rc::new(Timer::default());
    let copied = Rc::new(Cell::new(false));

    {
        let url = url.clone();
        let weak = ui.as_weak();
        ui.on_add_telegram(move || {
            if open::that(&url).is_err() {
                log::warn!("Cannot open Telegram link");
            }
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        });
    }
    {
        let url = url.clone();
        let weak = ui.as_weak();
        let timer = reset_timer.clone();
        let copied = copied.clone();
        ui.on_copy_link(move || {
            if arboard::Clipboard::new().and_then(|mut c| c.set_text(url.clone())).is_ok() {
                copied.set(true);
                if let Some(ui) = weak.upgrade() {
                    ui.set_copied(true);
                }
                let weak = weak.clone();
                timer.start(TimerMode::SingleShot, Duration::from_millis(1800), move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_copied(false);
                    }
                });
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_finish(move || {
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        });
    }

    let reveal_timer = Timer::default();
    {
        let weak = ui.as_weak();
        reveal_timer.start(TimerMode::SingleShot, Duration::from_millis(60), move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_shown(true);
            }
        });
    }

    if let Err(err) = ui.run() {
        log::error!("First-run window failed: {err}");
    }
    let _ = std::fs::write(&paths.first_run_marker, b"");
    std::process::exit(0);
}
