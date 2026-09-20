#!/usr/bin/env python3
"""Generate extension + desktop-web icon sizes from the 512px source icon.

Usage:
    python3 tools/gen-icons.py
Outputs extension/icons/icon-{16,32,48,128}.png
"""
import os
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(ROOT, "app", "icon-512.png")
OUTDIR = os.path.join(ROOT, "extension", "icons")

SIZES = [16, 32, 48, 128]

def main():
    if not os.path.exists(SRC):
        raise SystemExit("missing source icon: " + SRC)
    os.makedirs(OUTDIR, exist_ok=True)
    img = Image.open(SRC).convert("RGBA")
    for s in SIZES:
        out = os.path.join(OUTDIR, "icon-%d.png" % s)
        img.resize((s, s), Image.LANCZOS).save(out)
        print("wrote", out)
    print("done")

if __name__ == "__main__":
    main()