# CIPHER//NET Desktop (Tauri)

A Tauri v2 wrapper for the CIPHER//NET web app.
Uses your system WebView — no Chromium bundled, tiny binary.

## Structure

```
tauri/                        ← This folder
├── package.json
├── src-tauri/
│   ├── tauri.conf.json       ← App config
│   ├── Cargo.toml            ← Rust deps
│   ├── build.rs
│   └── src/
│       ├── main.rs
│       └── lib.rs            ← Tor detection + window setup
│
../                           ← Web app files (loaded directly)
├── index.html
├── app.js
├── app.css
└── ...
```

## Prerequisites

### 1. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Install Linux system dependencies
```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y \
  libwebkit2gtk-4.1-dev \
  build-essential \
  curl \
  wget \
  file \
  libxdo-dev \
  libssl-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev

# Fedora
sudo dnf install -y \
  webkit2gtk4.1-devel \
  openssl-devel \
  curl \
  wget \
  file \
  libappindicator-gtk3-devel \
  librsvg2-devel
```

### 3. Install Node.js / npm
```bash
# Via nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
nvm install --lts
```

## Development

```bash
cd tauri
npm install
npm run dev
```

This opens a native window loading `../index.html` directly.
Edit web app files and the window hot-reloads.

## Build

```bash
npm run build
```

Output: `src-tauri/target/release/bundle/`
- `.deb` package (Debian/Ubuntu)
- `.AppImage` (portable, runs on any Linux x86_64)
- `.rpm` (Fedora, optional)

## Why Tauri instead of Electrobun

| | Tauri | Electrobun |
|---|---|---|
| Linux x86_64 support | ✅ Stable | ❌ Pre-alpha, broken |
| Architecture detection | ✅ Automatic | ❌ Manual, unreliable |
| Binary size | ~5MB | ~100MB |
| Maturity | v2.0 stable | v0.0.x pre-alpha |
| WebView | System (WebKitGTK) | System (WebKitGTK) |
| Your web app works unchanged | ✅ | ✅ |

## Tor integration

`lib.rs` tries to connect to ports 9150, 9050, 9051 on startup.
If Tor is running, `window.__CIPHERNET_TOR_PROXY__` is set in the
WebView so `nostr.js` knows to route `.onion` relay connections
through it.

Start Tor Browser or `sudo systemctl start tor` before launching.
