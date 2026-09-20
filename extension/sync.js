'use strict';

// CIPHER//NET — Extension snapshot sync
//
// Mirrors the web layer (app/) into extension/app/, the folder bundled via
// manifest.json "app/index.html". The extension runs fully offline: the
// runtime CDN import for post-quantum keys is blocked by MV3 CSP, so the
// bundled local files (noble-post-quantum.js, ml-dsa.js, ml-kem.js) are used.
//
//   node sync.js        # refresh the extension snapshot
//
// sw.js is deliberately excluded — page service workers cannot register on
// extension origins (MV3 uses the extension's own background service worker).

const fs   = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', 'app');    // app/ (web source of truth)
const APP  = path.join(__dirname, 'app');          // extension snapshot dir

const EXCLUDE = new Set([
  'sw.js',              // page SW — not registerable on extension origins
  'tauri',              // never nest the desktop project into the extension
  '.github',
  'landing.html',
  'README.md',
  'download-noble-pq.sh',
  'embed-fonts.py',
  '.git',
  '.gitignore',
]);

if (!fs.existsSync(path.join(ROOT, 'index.html'))) {
  console.error('extension/sync: expected app/index.html at ' + ROOT);
  process.exit(1);
}

fs.rmSync(APP, { recursive: true, force: true });
fs.mkdirSync(APP, { recursive: true });

for (const entry of fs.readdirSync(ROOT)) {
  if (EXCLUDE.has(entry)) continue;
  const src = path.join(ROOT, entry);
  const dst = path.join(APP, entry);
  fs.cpSync(src, dst, { recursive: true });
}

console.log('extension/sync: snapshot refreshed -> ' + APP);