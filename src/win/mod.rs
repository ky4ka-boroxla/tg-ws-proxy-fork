pub mod autostart;
pub mod dialogs;
pub mod first_run_ui;
pub mod host;
pub mod settings_ui;
pub mod singleton;
pub mod theme;
pub mod tr_gen;
pub mod tray;
pub mod ui;
pub mod ui_common;

pub const EXIT_SETTINGS_NO_CHANGE: i32 = 0;
pub const EXIT_SETTINGS_SAVED: i32 = 10;
pub const EXIT_SETTINGS_SAVED_RESTART: i32 = 11;
pub const EXIT_FIRST_RUN_OPEN_TELEGRAM: i32 = 20;

pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--settings") {
        settings_ui::run();
    } else if args.iter().any(|a| a == "--first-run") {
        first_run_ui::run();
    } else {
        tray::run();
    }
}
