# Downloading optional libraries for CIPHER//NET

---

## 1. noble-post-quantum (Post-Quantum Cryptography)

### The easy way — run the bundler script

From the `ciphernet/` root directory (where `index.html` lives):

```bash
bash download-noble-pq.sh
```

This requires Node.js + npm. It installs `@noble/post-quantum@0.4.1` locally,
bundles it with esbuild into a single `noble-post-quantum.js` file, and saves
it to the current directory. Then copy it into `tauri/web/` if using Tauri:

```bash
cp noble-post-quantum.js tauri/web/
```

### Manual way

```bash
mkdir _pq && cd _pq
npm init -y
npm install @noble/post-quantum@0.4.1 esbuild

cat > entry.js << 'JS'
import { ml_dsa65 }  from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
export { ml_dsa65, ml_kem768 };
JS

npx esbuild entry.js \
  --bundle --format=esm --platform=browser \
  --target=es2020 --minify \
  --outfile=../noble-post-quantum.js

cd .. && rm -rf _pq
```

### What the app does without it

- Post-quantum algorithms (ML-DSA-65, ML-KEM-768) are unavailable
- Classical algorithms (ECDSA P-256/P-384, RSA-PSS) still work fine
- The esm.sh CDN is tried first when online — no local file needed for browser/GitHub Pages

---

## 2. openpgp.min.js (PGP / GPG / Kleopatra support)

```bash
# npm
npm install openpgp@5.11.2
cp node_modules/openpgp/dist/openpgp.min.js ./openpgp.min.js

# Or direct download
curl -L "https://unpkg.com/openpgp@5.11.2/dist/openpgp.min.js" -o openpgp.min.js
```

Then for Tauri:
```bash
cp openpgp.min.js tauri/web/
```

The file should be ~640KB.
Without it, PGP export/import/encrypt/decrypt features are disabled.
All other features work normally.
