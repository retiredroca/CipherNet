# CIPHER//NET — AGENTS.md

## Project
Self-hosted, end-to-end encrypted chat. No servers, no accounts. Static HTML/JS — deployable on any static host (including OnionShare).

## Architecture
- **Zero build step** — instant hosting, CSP-compatible
- **IIFE modules** — each file wraps in `window.CipherNet = window.CipherNet || {}; ... window.CipherNet.ModuleName = { ... }`
- **No bundler** — separate `<script src>` tags in `index.html`, loaded in strict dependency order
- **Cross-module calls** — use `window.CipherNet.ModuleName.fn()`

## Module Dependency Order (load order in index.html)
1. `openpgp.min.js` — global `openpgp`
2. `channels.js` — global `window.CipherChannels`
3. `nostr.js` — global `window.CipherNostr`
4. `lib/crypto.js` — `CipherNet.Crypto` (pure crypto)
5. `lib/util.js` — `CipherNet.Util` ($, toast, escHtml, helpers)
6. `lib/state.js` — `CipherNet.State` (state object, getStoredUsers)
7. `lib/render.js` — `CipherNet.Render` (renderMessage, updateMsgInput, etc.)
8. `lib/messaging.js` — `CipherNet.Messaging` (send/receive/persist/DMs)
9. `lib/lock-screen.js` — `CipherNet.LockScreen` (generate/import/enter)
10. `lib/identity.js` — `CipherNet.Identity` (export/backup/file import)
11. `lib/deterrents.js` — `CipherNet.Deterrents` (screen/PrintScreen/kbd blocking)
12. `lib/theme.js` — `CipherNet.Theme` (theme switcher + own DOMContentLoaded)
13. `lib/pgp-ui.js` — `CipherNet.PGP` (PGP modal + own DOMContentLoaded)
14. `lib/nostr-ui.js` — `CipherNet.NostrUI` (Nostr UI + own DOMContentLoaded)
15. `lib/channel-ui.js` — `CipherNet.ChannelUI` (channel manager + own DOMContentLoaded)
16. `lib/boot.js` — `CipherNet.Boot` (core DOMContentLoaded, SW registration)

## Key Conventions
- `$('id')` — shorthand for `document.getElementById`
- `toast(msg)` — user-facing notification
- `escHtml(s)` — escape &, <, > for safe innerHTML
- `state` — mutable global state object at `CipherNet.State.state`
- All crypto primitives go through `CipherNet.Crypto.*`
- All encryption uses AES-256-GCM; signing uses ECDSA/ML-DSA/RSA-PSS

## Verification
```
# Serve locally and test in browser
cd app && python3 -m http.server 8080
# Or any static file server
```
Open browser console, check for errors. Exercise:
1. Generate keys (both PQ and classical)
2. Import key
3. Send/receive channel messages
4. Send/receive DMs
5. PGP export/import/encrypt/decrypt
6. Nostr relay connection
7. Channel create/join/settings

## Known Issues
- Nostr secp256k1 private key stored as plain base64 in localStorage (`cipher_nostr_priv`) — should be encrypted with PBKDF2+AES
- Post-quantum lib loads from esm.sh CDN (external request) — bundle offline for true zero-external-dependency
