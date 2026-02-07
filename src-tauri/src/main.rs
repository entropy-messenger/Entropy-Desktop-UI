
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod audio;
mod app_state;
mod commands;
#[cfg(test)]
mod tests;

use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
    Manager,
};
use app_state::{DbState, NetworkState, AudioState};
use audio::AudioRecorder;

fn main() {
    let profile = std::env::var("ENTROPY_PROFILE").unwrap_or_else(|_| "default".to_string());
    println!("[*] Starting Entropy (Profile: {})", profile);

    tauri::Builder::default()
        .manage(DbState {
            conn: Mutex::new(None),
        })
        .manage(NetworkState {
            queue: Mutex::new(std::collections::VecDeque::new()),
            sender: Mutex::new(None),
        })
        .manage(AudioState {
            recorder: Mutex::new(AudioRecorder::new()),
        })
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::init_vault,
            commands::vault_save,
            commands::vault_load,
            commands::crypto_sha256,
            commands::connect_network,
            commands::send_to_network,
            commands::flush_outbox,
            commands::nuclear_reset,
            commands::crypto_mine_pow,
            commands::clear_vault,
            commands::vault_exists,
            commands::vault_delete,
            commands::start_native_recording,
            commands::stop_native_recording,
            commands::save_file,
            commands::export_database,
            commands::import_database
        ])
        .setup(|app| {
            // Setup tray and menu as before
            let quit_i = MenuItem::with_id(app, "quit", "Quit Entropy", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        app.exit(0);
                    }
                    "show" => {
                        let window = app.get_webview_window("main").unwrap();
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { .. } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
