# CIPHER//NET Desktop (Tauri)

## Project structure

```
tauri/
├── setup.sh                 ← Run this first — copies web files into web/
├── package.json
├── web/                     ← Web app files (created by setup.sh)
│   ├── index.html
│   ├── app.js
│   ├── app.css
│   ├── channels.js
│   ├── nostr.js
│   └── ...
└── src-tauri/
    ├── tauri.conf.json      ← frontendDist: "../web"
    ├── Cargo.toml
    ├── build.rs
    ├── icons/icon.png
    └── src/
        ├── main.rs
        └── lib.rs
```

## Prerequisites (one time)

### 1. Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Linux system dependencies
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y \
  libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev

# Fedora
sudo dnf install -y \
  webkit2gtk4.1-devel openssl-devel curl wget file \
  libappindicator-gtk3-devel librsvg2-devel
```

### 3. Node.js
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
nvm install --lts
```

## Setup & run

```bash
cd tauri

# 1. Copy web app files into web/ folder (required before dev or build)
bash setup.sh

# 2. Install JS deps (first time only)
npm install

# 3. Dev mode
npm run dev

# 4. Production build
npm run build
# Output: src-tauri/target/release/bundle/
```

## After updating web files

```bash
bash setup.sh   # re-copy updated files
npm run dev     # or npm run build
```

---

## Tor integration

`lib.rs` probes 9150 → 9050 → 9051 at startup.
If Tor is running, `window.__CIPHERNET_TOR_PROXY__` is set in the
WebView so `nostr.js` routes `.onion` relays through it.

---

## Common errors

**Blank page:** Run `bash setup.sh` first to populate `web/`.

**frontendDist error:** Ensure `tauri.conf.json` has `"frontendDist": "../web"` and `web/index.html` exists.

**Identifier ends with .app:** Fixed — now `net.ciphernet.chat`.
