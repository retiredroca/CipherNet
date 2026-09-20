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
2. `secp256k1.js` — vendored global `window.nobleSecp256k1` (`{schnorr, secp256k1}`)
3. `channels.js` — global `window.CipherChannels`
4. `nostr.js` — global `window.CipherNostr`
5. `lib/crypto.js` — `CipherNet.Crypto` (pure crypto)
6. `lib/util.js` — `CipherNet.Util` ($, toast, escHtml, helpers)
7. `lib/state.js` — `CipherNet.State` (state object, getStoredUsers)
8. `lib/wordlist.js` — `CipherNet.Bip39` (BIP-39 recovery phrases)
9. `lib/render.js` — `CipherNet.Render` (renderMessage, updateMsgInput, etc.)
10. `lib/messaging.js` — `CipherNet.Messaging` (send/receive/persist/DMs)
11. `lib/lock-screen.js` — `CipherNet.LockScreen` (generate/import/enter)
12. `lib/guest.js` — `CipherNet.Guest` (temporary guest entry, recovery-phrase persist/unlock)
13. `lib/identity.js` — `CipherNet.Identity` (export/backup/file import)
14. `lib/deterrents.js` — `CipherNet.Deterrents` (screen/PrintScreen/kbd blocking)
15. `lib/theme.js` — `CipherNet.Theme` (theme switcher + own DOMContentLoaded)
16. `lib/pgp-ui.js` — `CipherNet.PGP` (PGP modal + own DOMContentLoaded)
17. `lib/nostr-ui.js` — `CipherNet.NostrUI` (Nostr UI + own DOMContentLoaded)
18. `lib/channel-ui.js` — `CipherNet.ChannelUI` (channel manager + own DOMContentLoaded)
19. `lib/boot.js` — `CipherNet.Boot` (core DOMContentLoaded, SW registration)

## Key Conventions
- `$('id')` — shorthand for `document.getElementById`
- `toast(msg)` — user-facing notification
- `escHtml(s)` — escape &, <, > for safe innerHTML
- `state` — mutable global state object at `CipherNet.State.state`
- All crypto primitives go through `CipherNet.Crypto.*`
- All encryption uses AES-256-GCM; signing uses ECDSA/ML-DSA/RSA-PSS
- Channel AES keys are **deterministic** (PBKDF2 600k, salt = `SHA-256("ciphernet-channel-v2:" + channelId)`). NEVER time/random-salt channel key derivation — it breaks decryption of shared history across devices/users. Ciphertext uniqueness comes from per-message random IVs; identity packs use a fresh random salt+IV per save; identity/DM/Nostr keys are CSPRNG-generated.

## Verification
```
# Serve locally and test in browser
cd app && python3 -m http.server 8080
# Or any static file server
```
Stop the local dev server when testing is done (Windows: find the PID with
`netstat -ano | findstr :8080` and `taskkill /PID <pid> /F`).

Open browser console, check for errors. Exercise:
1. Generate keys (both PQ and classical)
2. Import key
3. Send/receive channel messages
4. Send/receive DMs
5. PGP export/import/encrypt/decrypt
6. Nostr relay connection
7. Channel create/join/settings

## Known Issues
- Post-quantum lib prefers esm.sh CDN first, then falls back to the bundled local files (`noble-post-quantum.js`, `ml-dsa.js`, `ml-kem.js`, `noble-pq-wrap.js`) — a build that tries esm.sh ONLY (removing the local fallback) is the remaining external-request. Keep the local files for offline/OnionShare.
- secp256k1 is vendored (`secp256k1.js`) and preferred; `nostr.js` still keeps an esm.sh fallback import when the vendored global is missing.
- Guest `cipher_identity_pack` is wrapped with PBKDF2-SHA-256 600k + AES-GCM and the recovery phrase is never stored — but the persist modal only *shows* the phrase once; no copy-all button backups to a file yet.
- Channel/`openpgp` PGP keys are not backed up automatically — use **Export backup** from the identity sidebar (independently of the extension's own localStorage).
- Guest sessions persist no Nostr keys (transport pubkey is regenerated per unlock) — saved identities will see a different Nostr pubkey after unlock.
