# CIPHER//NET — Browser Extension

Run CIPHER//NET from your browser with **no server, no account, no hosting** —
every asset is bundled locally. Click the toolbar icon and the app opens in a
full tab; it also works fully offline.

## Build

```bash
node sync.js        # mirror app/ into extension/app/
python3 tools/gen-icons.py   # generate toolbar icons (PIL)
```

You can also skip the icon step — the repo ships the generated `icons/`.

## Install (source build)

Extensions are intentionally **not published to the stores**; install from
source instead.

### Chrome / Edge / Brave / Chromium
1. `chrome://extensions` (Edge: `edge://extensions`)
2. Toggle **Developer mode** on
3. **Load unpacked** → select this `extension/` folder

### Firefox / LibreWolf
1. `about:debugging#/runtime/this-firefox`
2. **Load Temporary Add-on…** → select `extension/manifest.json`

>Temporary add-ons are removed when the browser restarts. For a permanent
>install you must sign the `.xpi` through AMO (addons.mozilla.org) — or keep
>using the temporary add-on and reinstall after restarts (30 seconds).

## What's included / adapted for extension context

- `app/` is a synced snapshot of the web layer (`node sync.js` re-mirrors it).
- `sw.js` is **excluded** — page service workers can't register on extension
  origins (MV3 uses the extension's own background service worker).
- The esm.sh post-quantum import is blocked by the extension's CSP; the bundled
  local files (`noble-post-quantum.js`, `ml-dsa.js`, `ml-kem.js`) are used.
- Identities persist in the extension's `localStorage` — use **Export backup**
  to keep them independently.
- Nostr relays connect directly from the extension page (no host permission
  needed); `.onion` relays require a Tor browser context, same as the web app.

## Web app vs extension — functional differences

| Concern | Web app (`app/`) | Extension (`extension/app/`) |
|---|---|---|
| **Offline cache** | PWA service worker (`sw.js`, `CACHE=ciphernet-v11`) — runtime caching + preload | **No `sw.js`** — page SWs can't register on extension origins (MV3 uses its own background worker). Offline is free: assets are bundled locally. |
| **Post-quantum lib** | Tries **esm.sh CDN** first, falls back to bundled local `noble-post-quantum.js` / `ml-dsa.js` / `ml-kem.js` | MV3 CSP **blocks esm.sh** → always uses the bundled local PQ files (`noble-post-quantum.js`, `ml-dsa.js`, `ml-kem.js`). Fully offline from first load. |
| **CSP / Web Crypto** | Needs HTTPS, localhost, or `.onion` origin | Stricter MV3 CSP, but Web Crypto is identical — no remote code. |
| **Nostr `.onion` relays** | Only connect when page itself is served from a `.onion` origin (`isTorContext()` = `location.hostname.endsWith('.onion')`) | Never a `.onion` origin → Tor-only relays skipped; clearnet `wss://` relays connect directly (no host permission needed). |
| **Identity / DM keys** | `localStorage` under the hosting origin (`.onion` or your static host) | `localStorage` under the `moz-extension://` origin — same code, separate storage realm. |
| **Launch** | Browser tab / PWA install (desktop PWA supported) | MV3 `background.js` worker opens `app/index.html` in a full tab on toolbar click. |
| **Vendored PQ deps** | esm.sh-first with local fallback | Local files always used — off by default at web, mandatory here. |

**Identical by design** (byte-for-byte after `node sync.js`): crypto (PQ + classical), channels, DMs, PGP UI, Nostr UI, deterrents, identity/guest flow, layout. `extension/app` is a snapshot of `app/` minus `sw.js` + build helpers (`download-noble-pq.sh`, `embed-fonts.py`).

**Practical takeaway:** the web app needs network for PQ the first time unless you bundle the local PQ files (OnionShare/Tor offline); the extension never does. The web app also hot-swaps assets on reload via its SW; the extension only updates when you reinstall the XPI.

## Manual verification

1. Load unpacked (steps above).
2. Click the **CIPHER//NET** toolbar icon.
3. Generate keys (PQ + classical), import, send a channel message.
4. Open the browser console (`F12`) — expect:
   `[CIPHER//NET] ⚛ PQ ready — ml_dsa65 and ml_kem768 available`
   (`[Nostr] Connected to …` lines once relays connect).