/**
 * CIPHER//NET — Electrobun Main Process
 * File: src/bun/index.ts
 *
 * Runs in the Bun main process. Creates the app window,
 * detects Tor proxy, and handles IPC with the WebView.
 */

import { BrowserWindow } from "electrobun/bun";
import path from "path";

// ── Tor SOCKS5 proxy detection ────────────────────────────
// Checks ports used by Tor Browser (9150) and system Tor (9050/9051)
const TOR_PORTS = [9150, 9050, 9051];
let torProxy: string | null = null;

async function detectTor(): Promise<string | null> {
  for (const port of TOR_PORTS) {
    try {
      const conn = await Bun.connect({
        hostname: "127.0.0.1",
        port,
        socket: {
          data() {},
          open() {},
          close() {},
          error() {},
        },
      });
      conn.end();
      console.log(`[CIPHER//NET] Tor detected on port ${port}`);
      return `socks5://127.0.0.1:${port}`;
    } catch {
      // Not available on this port
    }
  }
  console.log("[CIPHER//NET] No Tor proxy detected");
  return null;
}

// ── Main ──────────────────────────────────────────────────
async function main() {
  console.log("[CIPHER//NET] Starting desktop app...");

  torProxy = await detectTor();

  const win = new BrowserWindow({
    title: "CIPHER//NET",
    url: "views://ui/index.html",
    width: 1100,
    height: 780,
    minWidth: 800,
    minHeight: 600,
  });

  // Inject desktop flags into the WebView before page scripts run
  await win.webview.executeJavaScript(`
    window.__CIPHERNET_DESKTOP__ = true;
    window.__CIPHERNET_TOR_PROXY__ = ${JSON.stringify(torProxy)};
    console.log('[CIPHER//NET] Desktop mode | Tor:', ${JSON.stringify(torProxy)});
  `);

  console.log("[CIPHER//NET] Window ready");
}

main().catch(console.error);
