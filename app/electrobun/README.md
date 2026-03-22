# CIPHER//NET Desktop (Electrobun)

This folder contains the Electrobun desktop app wrapper.
The web app files (`index.html`, `app.js`, `app.css` etc.) live in the parent directory and are served directly.

## Requirements

- [Bun](https://bun.sh) v1.0+
- [Electrobun](https://electrobun.dev) (installed via `bun install`)

## Setup

```bash
cd electrobun
bun install
```

## Development

```bash
bun run dev
```

Opens a native desktop window serving the app from `../` on `localhost:3131`.
Hot reload: edit files in `../`, refresh the window (Cmd/Ctrl+R).

## Production build

```bash
bun run build
```

Produces a self-contained native app bundle in `./dist/`.

---

## Tor integration

CIPHER//NET Desktop automatically detects a running Tor proxy:

| Port | Source |
|------|--------|
| 9150 | Tor Browser |
| 9050 | System Tor (`tor` daemon) |
| 9051 | Alternative system Tor |

If detected, the proxy address is injected as `window.__CIPHERNET_TOR_PROXY__`
so `nostr.js` can route `.onion` relay connections through it.

**To use Tor with CIPHER//NET Desktop:**
1. Start Tor Browser or install `tor` and run `sudo systemctl start tor`
2. Launch CIPHER//NET Desktop — it detects Tor automatically
3. Add `.onion` Nostr relays in the Relay Settings panel
4. All WebSocket connections to `.onion` addresses route through Tor

---

## Architecture

```
electrobun/
├── package.json       — Bun/Electrobun project
├── src/
│   └── main.ts        — Main process: window, dev server, Tor detection
└── README.md          — This file

../                    — Web app (shared with browser deployment)
├── index.html
├── app.js
├── app.css
├── nostr.js           — Nostr/Tor P2P layer
├── sw.js              — Service worker (PWA)
└── ...
```

---

## Desktop vs Browser differences

| Feature | Browser | Desktop |
|---|---|---|
| Web Crypto API | ✓ | ✓ (WebView) |
| localStorage | ✓ | ✓ (WebView) |
| Nostr WebSocket | ✓ | ✓ |
| Tor .onion relays | Tor Browser only | ✓ Auto-detected |
| PWA install | ✓ | N/A (native app) |
| `window.__CIPHERNET_DESKTOP__` | `false` | `true` |
| `window.__CIPHERNET_TOR_PROXY__` | `null` | `"socks5://127.0.0.1:9150"` or `null` |
