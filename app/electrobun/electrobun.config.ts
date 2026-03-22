import type { ElectrobunConfig } from "electrobun";

export default {
  app: {
    name: "CIPHERNET",
    identifier: "net.ciphernet.app",
    version: "1.0.0",
  },
  build: {
    bun: {
      entrypoint: "src/bun/index.ts",
    },
    views: {
      ui: {
        entrypoint: "src/ui/index.html",
      },
    },
    // Copy web app files into the ui view at build time.
    // Place all CIPHER//NET web files in the electrobun/ folder
    // alongside package.json, or adjust these paths to point to
    // the parent directory if using a monorepo layout.
    copy: {
      "app.js":       "views/ui/app.js",
      "app.css":      "views/ui/app.css",
      "channels.js":  "views/ui/channels.js",
      "nostr.js":     "views/ui/nostr.js",
    },
  },
} satisfies ElectrobunConfig;
