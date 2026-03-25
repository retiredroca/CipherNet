use std::net::TcpStream;
use std::time::Duration;
use tauri::Manager;

fn detect_tor() -> Option<String> {
    let ports = [9150u16, 9050, 9051];
    for port in ports {
        if TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(500),
        )
        .is_ok()
        {
            println!("[CIPHER//NET] Tor detected on port {}", port);
            return Some(format!("socks5://127.0.0.1:{}", port));
        }
    }
    println!("[CIPHER//NET] No Tor proxy detected");
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let tor_proxy = detect_tor();

    tauri::Builder::default()
        .setup(move |app| {
            let window = app.get_webview_window("main").unwrap();

            let tor_json = serde_json::to_string(&tor_proxy).unwrap_or("null".into());
            let script = format!(
                "window.__CIPHERNET_DESKTOP__ = true; \
                 window.__CIPHERNET_TOR_PROXY__ = {};",
                tor_json
            );
            window.eval(&script).ok();

            println!("[CIPHER//NET] Desktop app started | Tor: {:?}", tor_proxy);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running CIPHER//NET");
}
