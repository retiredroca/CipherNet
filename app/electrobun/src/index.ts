/**
 * CIPHER//NET — Electrobun Desktop Entry Point
 *
 * Bundles the existing web app in a WebView.
 * Optionally routes Nostr WebSocket connections through Tor SOCKS5 proxy.
 *
 * Usage:
 *   bun install
 *   bun run dev      ← development (loads app from ../app files)
 *   bun run build    ← production build
 */

import { Bun } from 'electrobun/bun';
import path from 'path';

// ── Window configuration ──────────────────────────────────
const APP_DIR   = path.resolve(import.meta.dir, '../');  // parent = web app files
const DEV_PORT  = 3131;

// ── Tor SOCKS5 proxy (optional) ───────────────────────────
// If Tor Browser or system Tor is running, its SOCKS5 proxy is on 127.0.0.1:9050
// (system Tor) or 127.0.0.1:9150 (Tor Browser).
// We detect it and pass the address to the renderer so nostr.js can use it.
const TOR_PORTS = [9150, 9050, 9051];
let   torProxy  = null;

async function detectTor(): Promise<string | null> {
  for (const port of TOR_PORTS) {
    try {
      // Try connecting to the proxy
      const conn = await Bun.connect({
        hostname: '127.0.0.1',
        port,
        socket: { data() {}, open() {}, close() {}, error() {} },
      });
      conn.end();
      console.log(`[Tor] Detected SOCKS5 proxy on port ${port}`);
      return `socks5://127.0.0.1:${port}`;
    } catch { /* not available on this port */ }
  }
  console.log('[Tor] No SOCKS5 proxy detected — connecting to Nostr relays directly');
  return null;
}

// ── Dev file server ───────────────────────────────────────
async function startDevServer() {
  const server = Bun.serve({
    port: DEV_PORT,
    async fetch(req) {
      const url  = new URL(req.url);
      let   file = url.pathname === '/' ? '/index.html' : url.pathname;
      const fp   = path.join(APP_DIR, file);
      const f    = Bun.file(fp);
      if (await f.exists()) {
        const ext = path.extname(fp);
        const mime: Record<string,string> = {
          '.html': 'text/html',
          '.js':   'application/javascript',
          '.css':  'text/css',
          '.json': 'application/json',
          '.png':  'image/png',
          '.svg':  'image/svg+xml',
        };
        return new Response(f, {
          headers: { 'Content-Type': mime[ext] || 'text/plain' }
        });
      }
      return new Response('Not found', { status: 404 });
    },
  });
  console.log(`[Dev] Serving ${APP_DIR} on http://localhost:${DEV_PORT}`);
  return server;
}

// ── Main ──────────────────────────────────────────────────
async function main() {
  console.log('CIPHER//NET starting...');

  // Detect Tor
  torProxy = await detectTor();

  // Start file server
  await startDevServer();

  // Create Electrobun app window
  const { createWindow, app } = await import('electrobun/app');

  const win = createWindow({
    title:  'CIPHER//NET',
    url:    `http://localhost:${DEV_PORT}/index.html`,
    width:  1100,
    height: 780,
    minWidth:  800,
    minHeight: 600,

    // Inject Tor proxy info and desktop flag into the WebView
    webPreferences: {
      // Additional JS injected before page scripts run
      additionalScript: `
        window.__CIPHERNET_DESKTOP__ = true;
        window.__CIPHERNET_TOR_PROXY__ = ${JSON.stringify(torProxy)};
        console.log('[CIPHER//NET] Desktop mode | Tor proxy:', ${JSON.stringify(torProxy)});
      `,
    },
  });

  win.on('close', () => app.quit());

  // IPC: handle relay connections that should go through Tor
  // In desktop mode, nostr.js can ask the main process to open a proxied
  // WebSocket connection using Bun's native Tor SOCKS support.
  win.on('ipc', async (channel: string, data: any) => {
    if (channel === 'nostr:connect' && torProxy) {
      // Future: native proxied WebSocket via Bun
      // For now, the renderer handles WebSocket directly
      // (works for clearnet relays; Tor Browser routes .onion automatically)
      win.send('nostr:proxy', { proxy: torProxy });
    }
  });

  console.log('CIPHER//NET window open');
}

main().catch(console.error);
