'use strict';

const CACHE = 'ciphernet-v1';
const ASSETS = [
  './',
  './index.html',
  './app.css',
  './lib/crypto.js',
  './lib/util.js',
  './lib/state.js',
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
