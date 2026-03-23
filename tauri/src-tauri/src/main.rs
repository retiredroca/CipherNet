// CIPHER//NET — Tauri Desktop App
// This file is intentionally minimal — all app logic is in the web layer.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ciphernet_lib::run()
}
