/*
 * CIPHER//NET — Self-hosted, end-to-end encrypted chat
 * Copyright (C) 2024 retiredroca
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Source code: https://github.com/retiredroca/CipherNet
 */
'use strict';

const CACHE = 'ciphernet-v11';
const ASSETS = [
  './',
  './index.html',
  './app.css',
  './pq-loader.js',
  './openpgp.min.js',
  './secp256k1.js',
  './channels.js',
  './nostr.js',
  './lib/crypto.js',
  './lib/util.js',
  './lib/state.js',
  './lib/wordlist.js',
  './lib/guest.js',
  './lib/render.js',
  './lib/messaging.js',
  './lib/lock-screen.js',
  './lib/identity.js',
  './lib/deterrents.js',
  './lib/theme.js',
  './lib/pgp-ui.js',
  './lib/nostr-ui.js',
  './lib/channel-ui.js',
  './lib/boot.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  if (!e.request.url.startsWith(self.location.origin)) return;

  // Navigation requests (top-level page loads) → network-first, no offline fallback.
  // This guarantees visitors always get the fresh HTML after a deploy.
  if (e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request)
        .then(response => {
          // Only cache successful responses for subsequent subresource loads.
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE).then(cache => cache.put(e.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // All other requests (scripts, styles, images) → cache-first.
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(response => {
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE).then(cache => cache.put(e.request, clone));
        }
        return response;
      });
    })
  );
});
