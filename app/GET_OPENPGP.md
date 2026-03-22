# Download OpenPGP.js

Run ONE of these from the repo root before deploying:

## Option A — npm
```bash
npm install openpgp@5.11.2
cp node_modules/openpgp/dist/openpgp.min.js ./openpgp.min.js
```

## Option B — direct download
```bash
curl -L "https://unpkg.com/openpgp@5.11.2/dist/openpgp.min.js" -o openpgp.min.js
```

## Option C — browser
Go to: https://unpkg.com/openpgp@5.11.2/dist/openpgp.min.js
Save As → openpgp.min.js → place in repo root next to index.html

The file should be ~642 KB.

---

# noble-post-quantum (Post-Quantum Cryptography)

## No local file needed — loads from esm.sh CDN automatically

The app loads `@noble/post-quantum` automatically from `esm.sh` CDN which
bundles all dependencies into browser-compatible ES modules. No local file
is required for GitHub Pages or any online deployment.

**The app will work out of the box for online deployments.**

---

## For offline / OnionShare use (optional local fallback)

If you need to run CIPHER//NET completely offline (no internet access),
you can provide a local file as a fallback. The app will use it when
esm.sh is unreachable.

### How to get the file

The easiest way is to save the esm.sh bundle directly:

1. Open this URL in your browser while online:
   `https://esm.sh/@noble/post-quantum@0.4.1/ml-dsa.js`
2. Save the page as `noble-post-quantum.js` in your repo root
3. Repeat for `https://esm.sh/@noble/post-quantum@0.4.1/ml-kem.js`
   and save as `noble-pq-kem.js`

> **Note:** Recent GitHub releases of noble-post-quantum do NOT include
> a standalone `.js` file. Any file downloaded from the GitHub releases
> page will return `Not Found`. Use esm.sh or the npm approach below.

### npm approach
```bash
npm install @noble/post-quantum
# Copy the ESM sub-modules (not the package root)
cp node_modules/@noble/post-quantum/ml-dsa.js ./noble-post-quantum.js
```

The file should be ~180 KB.

Algorithms provided:
- ML-KEM-768 (FIPS 203) — post-quantum DM key encapsulation
- ML-DSA-65  (FIPS 204) — post-quantum message signing
