use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

use crate::app_config::{exe_path, has_ipv6, requires_restart, AppConfig, AppPaths};
use crate::i18n::{set_language, t, tf, Lang};
use crate::logging::{self, LogOptions};
use crate::utils::get_link_host;
use crate::win::dialogs::{show_error, show_info};
use crate::win::host::ProxyHost;
use crate::win::singleton::SingleInstance;
use crate::win::ui_common::load_icon_rgba;
use crate::win::{
    EXIT_FIRST_RUN_OPEN_TELEGRAM, EXIT_SETTINGS_SAVED, EXIT_SETTINGS_SAVED_RESTART,
};

#[derive(Debug)]
enum UserEvent {
    Menu(MenuEvent),
    Tray(TrayIconEvent),
    ConfigReloaded,
    OpenTelegram,
}

struct State {
    paths: AppPaths,
    config: Mutex<AppConfig>,
    host: ProxyHost,
    settings_open: std::sync::atomic::AtomicBool,
}

fn error_sink() -> Arc<dyn Fn(String, Option<&'static str>) + Send + Sync> {
    Arc::new(|message, link| {
        if let Some(link) = link {
            let _ = open::that(link);
        }
        show_error(&message);
    })
}

fn open_in_telegram(state: &State) {
    let url = state.config.lock().tg_proxy_url();
    log::info!("Opening {url}");
    if open::that(&url).is_ok() {
        return;
    }
    log::info!("Browser open failed, copying to clipboard");
    match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(url.clone())) {
        Ok(()) => show_info(&tf("dialog.open_tg_fail_clipboard", &[("url", &url)]), None),
        Err(_) => show_error(&tf("dialog.open_tg_fail_manual", &[("url", &url)])),
    }
}

fn copy_link(state: &State) {
    let url = state.config.lock().tg_proxy_url();
    log::info!("Copying link: {url}");
    if let Err(err) = arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(url)) {
        log::error!("Clipboard copy failed: {err}");
        show_error(&tf("dialog.copy_fail", &[("error", &err.to_string())]));
    }
}

fn open_logs(state: &State) {
    log::info!("Opening log file: {}", state.paths.log.display());
    if state.paths.log.exists() {
        if let Err(err) = open::that(&state.paths.log) {
            log::error!("Failed to open log file: {err}");
            show_error(&tf("dialog.log_open_fail", &[("error", &err.to_string())]));
        }
    } else {
        show_info(&t("dialog.log_not_found"), None);
    }
}

fn run_child(flag: &str) -> Option<i32> {
    let status = Command::new(exe_path()).arg(flag).status().ok()?;
    status.code()
}

fn edit_settings(state: Arc<State>, proxy: EventLoopProxy<UserEvent>) {
    if state.settings_open.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        let before = state.config.lock().clone();
        let code = run_child("--settings");
        let after = AppConfig::load(&state.paths.config);
        if matches!(code, Some(EXIT_SETTINGS_SAVED) | Some(EXIT_SETTINGS_SAVED_RESTART)) {
            let changed = before.changed_keys(&after);
            log::info!("Settings applied: {}", changed.iter().cloned().collect::<Vec<_>>().join(", "));
            set_language(Lang::parse(&after.language));
            *state.config.lock() = after.clone();
            let _ = proxy.send_event(UserEvent::ConfigReloaded);
            if code == Some(EXIT_SETTINGS_SAVED_RESTART) && requires_restart(&changed) {
                state.host.restart(&after, error_sink());
            }
        }
        state.settings_open.store(false, std::sync::atomic::Ordering::SeqCst);
    });
}

fn show_first_run(state: Arc<State>, proxy: EventLoopProxy<UserEvent>) {
    if state.paths.first_run_marker.exists() {
        return;
    }
    std::thread::spawn(move || {
        let code = run_child("--first-run");
        if !state.paths.first_run_marker.exists() {
            let _ = std::fs::write(&state.paths.first_run_marker, b"");
        }
        if code == Some(EXIT_FIRST_RUN_OPEN_TELEGRAM) {
            let _ = proxy.send_event(UserEvent::OpenTelegram);
        }
    });
}

fn check_ipv6_warning(state: &State) {
    if state.paths.ipv6_marker.exists() || !has_ipv6() {
        return;
    }
    let _ = std::fs::write(&state.paths.ipv6_marker, b"");
    std::thread::spawn(|| show_info(&t("ipv6.warning"), None));
}

fn load_tray_icon() -> Icon {
    let (rgba, width, height) = load_icon_rgba(Some(32)).unwrap_or_else(|| (vec![0, 136, 204, 255].repeat(32 * 32), 32, 32));
    Icon::from_rgba(rgba, width, height).expect("tray icon")
}

struct Menus {
    open: MenuItem,
    copy: MenuItem,
    restart: MenuItem,
    settings: MenuItem,
    logs: MenuItem,
    exit: MenuItem,
}

fn refresh_menu_text(menus: &Menus, config: &AppConfig) {
    let host = get_link_host(&config.host);
    menus.open.set_text(tf("tray.open_telegram", &[("host", &host), ("port", &config.port.to_string())]));
    menus.copy.set_text(t("tray.copy_link"));
    menus.restart.set_text(t("tray.restart"));
    menus.settings.set_text(t("tray.settings"));
    menus.logs.set_text(t("tray.logs"));
    menus.exit.set_text(t("tray.exit"));
}

pub fn run() {
    let paths = AppPaths::detect();
    let _ = paths.ensure();
    let config = AppConfig::load(&paths.config);
    set_language(Lang::parse(&config.language));

    let Some(_instance) = SingleInstance::acquire() else {
        show_info(&t("dialog.already_running"), Some("TgWsProxy.exe"));
        return;
    };

    let _ = logging::init(LogOptions {
        verbose: config.verbose,
        file: Some(paths.log.clone()),
        max_mb: config.log_max_mb,
        backups: 1,
        console: false,
    });
    if !paths.config.exists() {
        let _ = config.save(&paths.config);
    }

    let state = Arc::new(State {
        paths,
        config: Mutex::new(config.clone()),
        host: ProxyHost::default(),
        settings_open: std::sync::atomic::AtomicBool::new(false),
    });

    state.host.start(&config, error_sink());

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    {
        let menu_proxy = proxy.clone();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = menu_proxy.send_event(UserEvent::Menu(event));
        }));
        let tray_proxy = proxy.clone();
        TrayIconEvent::set_event_handler(Some(move |event| {
            let _ = tray_proxy.send_event(UserEvent::Tray(event));
        }));
    }

    let menus = Menus {
        open: MenuItem::new("", true, None),
        copy: MenuItem::new("", true, None),
        restart: MenuItem::new("", true, None),
        settings: MenuItem::new("", true, None),
        logs: MenuItem::new("", true, None),
        exit: MenuItem::new("", true, None),
    };
    refresh_menu_text(&menus, &config);
    let menu = Menu::new();
    let _ = menu.append_items(&[
        &menus.open,
        &menus.copy,
        &PredefinedMenuItem::separator(),
        &menus.restart,
        &menus.settings,
        &menus.logs,
        &PredefinedMenuItem::separator(),
        &menus.exit,
    ]);

    let mut tray = None;
    let startup_state = state.clone();
    let startup_proxy = proxy.clone();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                tray = TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_menu_on_left_click(false)
                    .with_tooltip(t("app.name"))
                    .with_icon(load_tray_icon())
                    .build()
                    .map_err(|err| log::error!("Cannot create tray icon: {err}"))
                    .ok();
                log::info!("Tray icon running");
                show_first_run(startup_state.clone(), startup_proxy.clone());
                check_ipv6_warning(&startup_state);
                let proxy = startup_proxy.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(1));
                    let _ = proxy.send_event(UserEvent::ConfigReloaded);
                });
            }
            Event::UserEvent(UserEvent::Tray(TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            })) => open_in_telegram(&state),
            Event::UserEvent(UserEvent::OpenTelegram) => open_in_telegram(&state),
            Event::UserEvent(UserEvent::ConfigReloaded) => {
                refresh_menu_text(&menus, &state.config.lock());
                if let Some(tray) = &tray {
                    let _ = tray.set_tooltip(Some(t("app.name")));
                }
            }
            Event::UserEvent(UserEvent::Menu(menu_event)) => {
                let id = menu_event.id;
                if id == menus.open.id() {
                    open_in_telegram(&state);
                } else if id == menus.copy.id() {
                    copy_link(&state);
                } else if id == menus.restart.id() {
                    let state = state.clone();
                    std::thread::spawn(move || {
                        let config = state.config.lock().clone();
                        state.host.restart(&config, error_sink());
                    });
                } else if id == menus.settings.id() {
                    edit_settings(state.clone(), proxy.clone());
                } else if id == menus.logs.id() {
                    open_logs(&state);
                } else if id == menus.exit.id() {
                    log::info!("User requested exit");
                    state.host.stop();
                    tray.take();
                    log::info!("Tray app exited");
                    *control_flow = ControlFlow::Exit;
                }
            }
            _ => {}
        }
    });
}
