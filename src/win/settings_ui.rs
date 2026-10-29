use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use parking_lot::Mutex;
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::app_config::{
    field_errors, link_from_form, requires_restart, validate_settings, AppConfig, AppPaths, FormValues,
};
use crate::config::{coerce_domain_text, default_cfproxy_domains, random_secret};
use crate::connectivity::{auto_report, cfproxy_auto_test, multi_report, multi_test, Report};
use crate::i18n::{set_language, t, tf, Lang};
use crate::update_check;
use crate::utils::get_link_host;
use crate::win::theme::{accent_index, accent_name, is_dark};
use crate::win::tr_gen;
use crate::win::ui::{ResultRow, SettingsWindow, Style};
use crate::win::ui_common::{qr_image, window_icon};
use crate::win::{autostart, EXIT_SETTINGS_NO_CHANGE, EXIT_SETTINGS_SAVED, EXIT_SETTINGS_SAVED_RESTART};

const DOCS_BASE: &str = "https://github.com/ky4ka-boroxla/tg-ws-proxy-fork/blob/main/docs/RU";
const LANGUAGES: [&str; 2] = ["ru", "en"];
const THEMES: [&str; 3] = ["auto", "light", "dark"];

struct State {
    paths: AppPaths,
    current: AppConfig,
    defaults: AppConfig,
    initial: FormValues,
    exit_code: i32,
    last_link: String,
}

type Shared = Rc<RefCell<State>>;

fn index_of(list: &[&str], value: &str) -> i32 {
    list.iter().position(|item| *item == value).unwrap_or(0) as i32
}

fn read_form(ui: &SettingsWindow) -> FormValues {
    FormValues {
        host: ui.get_host().to_string(),
        port: ui.get_port().to_string(),
        secret: ui.get_secret().to_string(),
        dc_ip: ui.get_dc_ip().to_string(),
        verbose: ui.get_verbose(),
        buf_kb: ui.get_buf_kb().to_string(),
        pool_size: ui.get_pool_size().to_string(),
        log_max_mb: ui.get_log_max_mb().to_string(),
        cfproxy: ui.get_cfproxy(),
        h2: ui.get_h2(),
        cfproxy_user_domain_enabled: ui.get_custom_enabled(),
        cfproxy_user_domain: ui.get_custom_domains().to_string(),
        cfproxy_worker_enabled: ui.get_worker_enabled(),
        cfproxy_worker_domain: ui.get_worker_domains().to_string(),
        force_test_dc: false,
        no_secure: ui.get_no_secure(),
        appearance: THEMES[ui.get_theme_index().clamp(0, 2) as usize].to_string(),
        accent: accent_name(ui.get_accent_index()).to_string(),
        language: LANGUAGES[ui.get_lang_index().clamp(0, 1) as usize].to_string(),
        autostart: ui.get_autostart(),
    }
}

fn write_form(ui: &SettingsWindow, form: &FormValues) {
    ui.set_host(form.host.clone().into());
    ui.set_port(form.port.clone().into());
    ui.set_secret(form.secret.clone().into());
    ui.set_dc_ip(form.dc_ip.clone().into());
    ui.set_verbose(form.verbose);
    ui.set_buf_kb(form.buf_kb.clone().into());
    ui.set_pool_size(form.pool_size.clone().into());
    ui.set_log_max_mb(form.log_max_mb.clone().into());
    ui.set_cfproxy(form.cfproxy);
    ui.set_h2(form.h2);
    ui.set_custom_enabled(form.cfproxy_user_domain_enabled);
    ui.set_custom_domains(form.cfproxy_user_domain.clone().into());
    ui.set_worker_enabled(form.cfproxy_worker_enabled);
    ui.set_worker_domains(form.cfproxy_worker_domain.clone().into());
    ui.set_no_secure(form.no_secure);
    ui.set_theme_index(index_of(&THEMES, &form.appearance));
    ui.set_accent_index(accent_index(&form.accent));
    ui.set_lang_index(index_of(&LANGUAGES, &form.language));
    ui.set_autostart(form.autostart);
}

fn apply_style(ui: &SettingsWindow, appearance: &str, accent: i32) {
    let style = ui.global::<Style>();
    style.set_dark(is_dark(appearance));
    style.set_accent_index(accent);
}

fn show_toast(ui: &SettingsWindow, timer: &Rc<Timer>, text: &str) {
    ui.set_toast(text.into());
    ui.set_toast_visible(true);
    let weak = ui.as_weak();
    timer.start(TimerMode::SingleShot, Duration::from_millis(2200), move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_toast_visible(false);
        }
    });
}

fn opt(text: Option<String>) -> SharedString {
    text.unwrap_or_default().into()
}

fn refresh(ui: &SettingsWindow, state: &Shared) {
    let form = read_form(ui);
    let errors = field_errors(&form);
    ui.set_host_error(opt(errors.host.clone()));
    ui.set_port_error(opt(errors.port.clone()));
    ui.set_secret_error(opt(errors.secret.clone()));
    ui.set_dc_error(opt(errors.dc.clone()));
    ui.set_has_errors(errors.any());
    ui.set_h2_available(form.cfproxy && !form.no_secure);

    let mut st = state.borrow_mut();
    ui.set_dirty(form != st.initial);
    match link_from_form(&form) {
        Some(link) => {
            ui.set_link_address(format!("{}:{}", get_link_host(form.host.trim()), form.port.trim()).into());
            if st.last_link != link {
                ui.set_qr(qr_image(&link));
                st.last_link = link.clone();
            }
            ui.set_link(link.into());
        }
        None => {
            ui.set_link("".into());
            st.last_link.clear();
        }
    }
}

fn rows_model(report: &Report) -> ModelRc<ResultRow> {
    let rows: Vec<ResultRow> = report
        .rows
        .iter()
        .map(|row| ResultRow { label: row.label.clone().into(), state: row.state, detail: row.detail.clone().into() })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

fn run_async<T: Send + 'static>(job: impl FnOnce(&tokio::runtime::Runtime) -> T + Send + 'static, done: impl FnOnce(T) + Send + 'static) {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
        if let Ok(runtime) = runtime {
            done(job(&runtime));
        }
    });
}

fn start_cf_test(ui: &SettingsWindow) {
    let form = read_form(ui);
    let secure = !form.no_secure;
    let custom = if form.cfproxy_user_domain_enabled { coerce_domain_text(&form.cfproxy_user_domain) } else { Vec::new() };
    ui.set_cf_running(true);
    let weak = ui.as_weak();
    run_async(
        move |runtime| {
            let title = t("connectivity.cfproxy_title");
            if !custom.is_empty() {
                let per = runtime.block_on(multi_test(&custom, false, secure));
                return multi_report(&title, &per, "kws");
            }
            let (domain, results) = runtime.block_on(cfproxy_auto_test(&default_cfproxy_domains(), secure));
            auto_report(&title, domain.as_deref(), &results, &t("connectivity.cf_auto_fail"))
        },
        move |report| {
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_cf_title(report.title.clone().into());
                ui.set_cf_state(report.state);
                ui.set_cf_rows(rows_model(&report));
                ui.set_cf_running(false);
            });
        },
    );
}

fn start_worker_test(ui: &SettingsWindow) {
    let form = read_form(ui);
    let domains = coerce_domain_text(&form.cfproxy_worker_domain);
    if !form.cfproxy_worker_enabled || domains.is_empty() {
        return;
    }
    let secure = !form.no_secure;
    ui.set_worker_running(true);
    let weak = ui.as_weak();
    run_async(
        move |runtime| {
            let per = runtime.block_on(multi_test(&domains, true, secure));
            multi_report(&t("connectivity.cfworker_title"), &per, "DC")
        },
        move |report| {
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_worker_title(report.title.clone().into());
                ui.set_worker_state(report.state);
                ui.set_worker_rows(rows_model(&report));
                ui.set_worker_running(false);
            });
        },
    );
}

fn start_update_check(ui: &SettingsWindow) {
    ui.set_update_running(true);
    ui.set_update_text("".into());
    ui.set_update_has(false);
    let weak = ui.as_weak();
    run_async(
        |runtime| {
            runtime.block_on(update_check::run_check(crate::VERSION));
            update_check::get_status()
        },
        move |status| {
            let _ = weak.upgrade_in_event_loop(move |ui| {
                let (text, has) = if status.error.is_some() {
                    (t("ui.update.failed"), false)
                } else if status.has_update {
                    (tf("ui.update.available", &[("version", status.latest.as_deref().unwrap_or(""))]), true)
                } else if status.ahead_of_release {
                    (t("ui.update.ahead"), false)
                } else {
                    (t("ui.up.to.date"), false)
                };
                ui.set_update_text(text.into());
                ui.set_update_has(has);
                ui.set_update_running(false);
                store_release_url(status.html_url.clone());
            });
        },
    );
}

static RELEASE_URL: Mutex<String> = Mutex::new(String::new());

pub fn store_release_url(url: String) {
    *RELEASE_URL.lock() = url;
}

fn try_save(ui: &SettingsWindow, state: &Shared) {
    let form = read_form(ui);
    let (current, defaults, config_path) = {
        let st = state.borrow();
        (st.current.clone(), st.defaults.clone(), st.paths.config.clone())
    };
    let new_config = match validate_settings(&form, &current, &defaults) {
        Ok(config) => config,
        Err(message) => {
            ui.set_banner(message.into());
            return;
        }
    };
    let changed = current.changed_keys(&new_config);
    if changed.is_empty() {
        let _ = ui.hide();
        return;
    }
    if let Err(err) = new_config.save(&config_path) {
        ui.set_banner(err.to_string().into());
        return;
    }
    log::info!("Settings saved: {}", changed.iter().cloned().collect::<Vec<_>>().join(", "));
    if changed.contains("autostart") {
        if let Err(err) = autostart::set_enabled(new_config.autostart) {
            log::error!("Failed to update autostart: {err}");
            ui.set_banner(tf("dialog.autostart_fail", &[("error", &err.to_string())]).into());
        }
    }
    {
        let mut st = state.borrow_mut();
        st.exit_code = EXIT_SETTINGS_SAVED;
        st.current = new_config;
        st.initial = form;
    }
    if requires_restart(&changed) {
        ui.set_ask_restart(true);
    } else {
        let _ = ui.hide();
    }
}

pub fn run() {
    let paths = AppPaths::detect();
    let _ = paths.ensure();
    let mut current = AppConfig::load(&paths.config);
    current.autostart = autostart::is_enabled();
    set_language(Lang::parse(&current.language));

    let ui = match SettingsWindow::new() {
        Ok(ui) => ui,
        Err(err) => {
            log::error!("Cannot create settings window: {err}");
            std::process::exit(EXIT_SETTINGS_NO_CHANGE);
        }
    };
    let initial = FormValues::from_config(&current);
    let state: Shared = Rc::new(RefCell::new(State {
        paths,
        current: current.clone(),
        defaults: AppConfig::default(),
        initial: initial.clone(),
        exit_code: EXIT_SETTINGS_NO_CHANGE,
        last_link: String::new(),
    }));

    let toast_timer = Rc::new(Timer::default());
    tr_gen::apply(&ui);
    ui.set_app_name(t("app.name").into());
    ui.set_version(crate::VERSION.into());
    ui.set_win_icon(window_icon());
    apply_style(&ui, &current.appearance, accent_index(&current.accent));
    write_form(&ui, &initial);
    refresh(&ui, &state);

    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_edited(move || {
            if let Some(ui) = weak.upgrade() {
                refresh(&ui, &state);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_save(move || {
            if let Some(ui) = weak.upgrade() {
                try_save(&ui, &state);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_cancel(move || {
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_reset(move || {
            if let Some(ui) = weak.upgrade() {
                let initial = state.borrow().initial.clone();
                write_form(&ui, &initial);
                set_language(Lang::parse(&initial.language));
                tr_gen::apply(&ui);
                apply_style(&ui, &initial.appearance, accent_index(&initial.accent));
                ui.set_banner("".into());
                refresh(&ui, &state);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_open_telegram(move || {
            if let Some(ui) = weak.upgrade() {
                let link = ui.get_link().to_string();
                if !link.is_empty() && open::that(&link).is_err() {
                    log::warn!("Cannot open Telegram link");
                }
            }
        });
    }
    {
        let weak = ui.as_weak();
        let timer = toast_timer.clone();
        ui.on_copy_link(move || {
            let Some(ui) = weak.upgrade() else { return };
            let link = ui.get_link().to_string();
            if link.is_empty() {
                return;
            }
            if arboard::Clipboard::new().and_then(|mut c| c.set_text(link)).is_ok() {
                show_toast(&ui, &timer, &t("ui.copied"));
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_generate_secret(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_secret(random_secret().into());
                refresh(&ui, &state);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_test_cf(move || {
            if let Some(ui) = weak.upgrade() {
                start_cf_test(&ui);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_test_worker(move || {
            if let Some(ui) = weak.upgrade() {
                start_worker_test(&ui);
            }
        });
    }
    ui.on_open_docs(|name| {
        let _ = open::that(format!("{DOCS_BASE}/{name}"));
    });
    {
        let state = state.clone();
        ui.on_open_log(move || {
            let path = state.borrow().paths.log.clone();
            if path.exists() {
                let _ = open::that(path);
            }
        });
    }
    {
        let state = state.clone();
        ui.on_open_folder(move || {
            let path = state.borrow().paths.dir.clone();
            let _ = open::that(path);
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_check_updates(move || {
            if let Some(ui) = weak.upgrade() {
                start_update_check(&ui);
            }
        });
    }
    ui.on_open_release(|| {
        let url = RELEASE_URL.lock().clone();
        let url = if url.is_empty() { update_check::RELEASES_PAGE_URL.to_string() } else { url };
        let _ = open::that(url);
    });
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_language_selected(move |index| {
            let code = LANGUAGES[(index.clamp(0, 1)) as usize];
            set_language(Lang::parse(code));
            if let Some(ui) = weak.upgrade() {
                tr_gen::apply(&ui);
                ui.set_app_name(t("app.name").into());
                refresh(&ui, &state);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_theme_selected(move |index| {
            if let Some(ui) = weak.upgrade() {
                let dark = is_dark(THEMES[(index.clamp(0, 2)) as usize]);
                ui.set_veil(true);
                let weak = ui.as_weak();
                Timer::single_shot(Duration::from_millis(60), move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.global::<Style>().set_dark(dark);
                        ui.set_veil(false);
                    }
                });
                refresh(&ui, &state);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_accent_selected(move |index| {
            if let Some(ui) = weak.upgrade() {
                ui.set_accent_index(index);
                ui.global::<Style>().set_accent_index(index);
                refresh(&ui, &state);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_restart_choice(move |restart| {
            if restart {
                state.borrow_mut().exit_code = EXIT_SETTINGS_SAVED_RESTART;
            }
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_dismiss_banner(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_banner("".into());
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
        log::error!("Settings window failed: {err}");
    }
    let code = state.borrow().exit_code;
    std::process::exit(code);
}
