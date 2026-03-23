#!/bin/bash
# Downloads and bundles @noble/post-quantum for offline browser use.
# Run this from the ciphernet/ root directory (where index.html lives).
#
# Requirements: node + npm (or bun)
#
# Usage:
#   bash download-noble-pq.sh

set -e

echo "Building noble-post-quantum browser bundle..."

# Work in a temp directory
TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Install the package
npm init -y > /dev/null
npm install @noble/post-quantum@0.4.1 > /dev/null 2>&1

# Write a bundler script
cat > bundle.mjs << 'BUNDLER'
import { ml_dsa65 }  from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

// Expose as globals for CIPHER//NET
globalThis.ml_dsa65  = ml_dsa65;
globalThis.ml_kem768 = ml_kem768;

// Write the bundle
import { writeFileSync } from 'fs';
const src = `
// noble-post-quantum browser bundle for CIPHER//NET
// Built from @noble/post-quantum@0.4.1
// Exposes: window.ml_dsa65, window.ml_kem768
`;
console.log('Bundle script loaded — use esbuild to bundle properly');
BUNDLER

# Use esbuild if available, otherwise use a simple node script
if command -v npx &> /dev/null; then
  npm install esbuild > /dev/null 2>&1

  # Create proper entry point
  cat > entry.js << 'ENTRY'
import { ml_dsa65 }  from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
export { ml_dsa65, ml_kem768 };
ENTRY

  npx esbuild entry.js \
    --bundle \
    --format=esm \
    --outfile=noble-post-quantum.js \
    --platform=browser \
    --target=es2020 \
    --minify \
    2>&1

  echo "Bundle created: $(wc -c < noble-post-quantum.js) bytes"
  cd -
  cp "$TMPDIR/noble-post-quantum.js" ./noble-post-quantum.js
  rm -rf "$TMPDIR"
  echo ""
  echo "✓ noble-post-quantum.js saved to $(pwd)/noble-post-quantum.js"
  echo "  Copy it into tauri/web/ as well:"
  echo "  cp noble-post-quantum.js tauri/web/"
else
  echo "ERROR: npx not found. Install Node.js first."
  rm -rf "$TMPDIR"
  exit 1
fi
