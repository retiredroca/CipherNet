# noble-post-quantum setup for CIPHER//NET

## Files needed (place all next to index.html)

```
index.html
ml-dsa.js          ← from @noble/post-quantum npm package
ml-kem.js          ← from @noble/post-quantum npm package
noble-pq-wrap.js   ← included in this zip — bridges ES modules to window globals
```

## How to get ml-dsa.js and ml-kem.js

```bash
npm install @noble/post-quantum@0.4.1
cp node_modules/@noble/post-quantum/ml-dsa.js ./ml-dsa.js
cp node_modules/@noble/post-quantum/ml-kem.js ./ml-kem.js
```

Or using curl (if the CDN works for you):
```bash
curl -L "https://unpkg.com/@noble/post-quantum@0.4.1/ml-dsa.js" -o ml-dsa.js
curl -L "https://unpkg.com/@noble/post-quantum@0.4.1/ml-kem.js"  -o ml-kem.js
```

## How it works

`noble-pq-wrap.js` fetches `ml-dsa.js` and `ml-kem.js` via XHR (same-origin,
CSP-safe), wraps them in blob URLs, and assigns `window.ml_dsa65` and
`window.ml_kem768`. This works under OnionShare's strict CSP.

## Without PQ files

The app falls back to ECDSA P-256 automatically. All other features work normally.

---

# openpgp.min.js (PGP / GPG support)

```bash
npm install openpgp@5.11.2
cp node_modules/openpgp/dist/openpgp.min.js ./openpgp.min.js
```

Place next to index.html. Without it, PGP features are disabled.
