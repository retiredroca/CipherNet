#!/bin/bash
# CIPHER//NET Tauri setup
# Run this from the tauri/ directory before npm run dev or npm run build
#
# Usage:
#   cd tauri
#   bash setup.sh
#   npm run dev      ← dev mode
#   npm run build    ← production build

set -e
PARENT=".."
WEB="./web"

echo "Copying web app files into $WEB/ ..."
mkdir -p "$WEB"

cp "$PARENT/index.html"   "$WEB/index.html"
cp "$PARENT/app.js"       "$WEB/app.js"
cp "$PARENT/app.css"      "$WEB/app.css"
cp "$PARENT/channels.js"  "$WEB/channels.js"
cp "$PARENT/nostr.js"     "$WEB/nostr.js"
cp "$PARENT/sw.js"        "$WEB/sw.js"
cp "$PARENT/manifest.json" "$WEB/manifest.json"
cp "$PARENT/icon-192.png" "$WEB/icon-192.png"
cp "$PARENT/icon-512.png" "$WEB/icon-512.png"

# Optional
[ -f "$PARENT/openpgp.min.js" ] && cp "$PARENT/openpgp.min.js" "$WEB/openpgp.min.js" && echo "Copied openpgp.min.js"

echo ""
echo "Done! Files in $WEB/:"
ls "$WEB/"
echo ""
echo "Now run:"
echo "  npm install    (first time only)"
echo "  npm run dev    (development)"
echo "  npm run build  (production)"
