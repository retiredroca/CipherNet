'use strict';

// CIPHER//NET — Tauri web snapshot sync
//
// The Tauri app embeds a snapshot of the web layer at tauri/web (referenced
// by tauri.conf.json frontendDist = "../web"). The landing/app source of
// truth lives in the parent directory. This script mirrors it into the
// snapshot so the desktop build always matches the served web app.
//
//   node sync-web.js        # refresh snapshot
//
// Run automatically before `tauri dev` / `tauri build` via package.json.

const fs   = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');         // app/ (web source of truth)
const WEB  = path.join(__dirname, 'web');        // snapshot dir

const EXCLUDE = new Set([
  'tauri',              // never nest the tauri project into itself
  '.github',
  'landing.html',       // duplicated by the GitHub Pages landing at repo root
  'README.md',
  'GET_OPENPGP.md',
  'download-noble-pq.sh',
  'embed-fonts.py',
  '.git',
  '.gitignore',
]);

if (!fs.existsSync(path.join(ROOT, 'index.html'))) {
  console.error('sync-web: expected app/index.html at ' + ROOT);
  process.exit(1);
}

fs.rmSync(WEB, { recursive: true, force: true });
fs.mkdirSync(WEB, { recursive: true });

for (const entry of fs.readdirSync(ROOT)) {
  if (EXCLUDE.has(entry)) continue;
  const src = path.join(ROOT, entry);
  const dst = path.join(WEB, entry);
  fs.cpSync(src, dst, { recursive: true });
}

console.log('sync-web: snapshot refreshed -> ' + WEB);