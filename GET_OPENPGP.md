# Optional local files for CIPHER//NET

All files go next to index.html. None are required — features degrade gracefully without them.

## OnionShare / strict CSP environments

OnionShare blocks ALL external requests and ALL inline scripts/styles.
Files must be local IIFE bundles (no export/import statements).

---

## noble-post-quantum (ML-DSA-65 + ML-KEM-768)

Build a CSP-safe IIFE bundle on your machine:

```bash
npm install @noble/post-quantum@0.4.1 esbuild

cat > pq-entry.js << 'JS'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
window.ml_dsa65  = ml_dsa65;
window.ml_kem768 = ml_kem768;
window._pqLoaded = true;
console.log('[PQ] noble-post-quantum ready');
JS

npx esbuild pq-entry.js \
  --bundle --format=iife --platform=browser --target=es2020 \
  --outfile=noble-post-quantum.js
```

Place `noble-post-quantum.js` next to `index.html`.

---

## secp256k1 (Nostr transport keys)

Required for Nostr P2P sync. Build a CSP-safe IIFE bundle:

```bash
npm install @noble/curves@1.4.0 esbuild

cat > secp-entry.js << 'JS'
import { schnorr } from '@noble/curves/secp256k1';
window.nobleSecp256k1 = { schnorr };
console.log('[Nostr] secp256k1 ready');
JS

npx esbuild secp-entry.js \
  --bundle --format=iife --platform=browser --target=es2020 \
  --outfile=secp256k1.js
```

Place `secp256k1.js` next to `index.html`.

---

## openpgp.min.js (PGP / GPG support)

```bash
npm install openpgp@5.11.2
cp node_modules/openpgp/dist/openpgp.min.js ./openpgp.min.js
```

Or:
```bash
curl -L "https://unpkg.com/openpgp@5.11.2/dist/openpgp.min.js" -o openpgp.min.js
```

---

## Quick build all three at once

```bash
npm install @noble/post-quantum@0.4.1 @noble/curves@1.4.0 openpgp@5.11.2 esbuild

# noble-post-quantum
echo "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
window.ml_dsa65=ml_dsa65; window.ml_kem768=ml_kem768; window._pqLoaded=true;" \
| npx esbuild --bundle --format=iife --platform=browser --outfile=noble-post-quantum.js

# secp256k1
echo "import { schnorr } from '@noble/curves/secp256k1';
window.nobleSecp256k1={schnorr};" \
| npx esbuild --bundle --format=iife --platform=browser --outfile=secp256k1.js

# openpgp
cp node_modules/openpgp/dist/openpgp.min.js ./openpgp.min.js

echo "Done. Copy noble-post-quantum.js, secp256k1.js, openpgp.min.js next to index.html"
```
