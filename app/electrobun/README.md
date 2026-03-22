# CIPHER//NET Desktop (Electrobun)

## Correct project structure

```
electrobun/
├── electrobun.config.ts   ← Electrobun config (required at root)
├── package.json
├── src/
│   ├── bun/
│   │   └── index.ts       ← Main process entry point
│   └── ui/
│       └── index.html     ← WebView shell
│
│   (place web app files here for build copying:)
├── app.js
├── app.css
├── channels.js
├── nostr.js
└── openpgp.min.js         ← optional
```

## Setup

```bash
cd electrobun

# Install dependencies
bun install

# Copy web app files into electrobun/ folder
cp ../app.js      ./app.js
cp ../app.css     ./app.css
cp ../channels.js ./channels.js
cp ../nostr.js    ./nostr.js
# Optional:
cp ../openpgp.min.js ./openpgp.min.js
```

## Run in development

```bash
bun run dev
```

## Build for production

```bash
bun run build
```

Output goes to `./dist/`.

---

## Tor integration

CIPHER//NET Desktop automatically detects a running Tor SOCKS5 proxy:

| Port | Source |
|------|--------|
| 9150 | Tor Browser |
| 9050 | System Tor (`tor` daemon) |
| 9051 | Alternative system Tor |

If detected, `window.__CIPHERNET_TOR_PROXY__` is set in the WebView.
Add `.onion` Nostr relays in the app's Relay Settings panel to route
traffic through Tor.

---

## Linux dependencies

WebKitGTK is required on Linux:

```bash
# Ubuntu/Debian
sudo apt install libwebkit2gtk-4.1-dev

# Fedora
sudo dnf install webkit2gtk4.1-devel
```
