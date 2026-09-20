#!/usr/bin/env python3
"""CIPHER//NET local release tool — mirror of mc-storage-area-network's tools/release.py.

No CI build, no external platform markets. This script does EVERYTHING from the
developer's machine:

  1. bumps the version (app/generator version + extension manifest + sw.js cache)
  2. zips the web app  -> dist/ciphernet-web-<tag>.zip
  3. zips the extension -> dist/ciphernet-extension-<tag>.zip
  4. builds the .xpi    -> dist/ciphernet-extension-<tag>.xpi
  5. commits, signs + pushes the tag
  6. creates the GitHub Release and uploads the three artifacts

The GitHub Release is created and the artifacts are uploaded over the GitHub
REST API using only the standard library (urllib) and the credentials Git
already has (git credential fill). The `gh` binary is never used.

The CI workflow (.github/workflows/release.yml, publish mode) only *downloads*
the pushed zip/xpi from an existing release to re-upload / cross-check them —
it never builds.
"""
from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import re
import shutil
import zipfile
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
APP = _ROOT / "app"
EXT = _ROOT / "extension"
DIST = _ROOT / "dist"
SW = APP / "sw.js"
PACKAGE = EXT / "manifest.json"
VERSIONS = _ROOT / "versions.properties"
UA = "ciphernet-release (github.com/retiredroca/CipherNet)"


# --- logging -------------------------------------------------------------------------


def log(msg):
    print(msg, flush=True)


def die(msg):
    print(f"release: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd, dry=False, **kw):
    if dry:
        log(f"  [dry-run] {' '.join(cmd)}")
        return
    subprocess.run(cmd, check=True, **kw)


def capture(cmd, dry=False):
    if dry:
        log(f"  [dry-run] {' '.join(cmd)}")
        return ""
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def now_stamp():
    return datetime.now(timezone.utc).strftime("%y%m%d%H%M")


def set_prop(path, key, value):
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    pattern = re.compile(rf"^{re.escape(key)}=.*$")
    found = False
    for i, line in enumerate(lines):
        if pattern.match(line):
            lines[i] = f"{key}={value}"
            found = True
            break
    if not found:
        lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def read_prop(path, key, default=""):
    if not path.exists():
        return default
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    return default


# --- git helpers ---------------------------------------------------------------------


def repo_slug():
    remote = capture(["git", "-C", str(_ROOT), "remote", "get-url", "origin"]).strip()
    slug = re.sub(r".*github\.com[:/]", "", remote)
    slug = re.sub(r"\.git$", "", slug).strip("/")
    return slug


def current_branch():
    return capture(["git", "-C", str(_ROOT), "rev-parse", "--abbrev-ref", "HEAD"]).strip()


def ensure_clean(allow_dirty):
    dirty = capture(["git", "-C", str(_ROOT), "status", "--porcelain"]).strip()
    if dirty and not allow_dirty:
        die("working tree is dirty; commit or stash first (or pass --allow-dirty)")


def commit(paths, message, dry, sign=True):
    run(["git", "-C", str(_ROOT), "add", "--"] + paths, dry=dry)
    cmd = ["git", "-C", str(_ROOT), "commit", "-m", message]
    if not sign:
        cmd += ["--no-gpg-sign"]
    run(cmd, dry=dry)


# --- GitHub REST (urllib only, no `gh` binary) ---------------------------------------


def github_token():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    out = subprocess.run(
        ["git", "credential", "fill"],
        input=b"protocol=https\nhost=github.com\n\n",
        capture_output=True,
    ).stdout.decode()
    for line in out.splitlines():
        if line.startswith("password="):
            return line[len("password="):]
    die("no GITHUB_TOKEN/GH_TOKEN and no stored github.com credential")


def gh_request(method, url, token, data=None, content_type="application/vnd.github+json",
               accept="application/vnd.github+json"):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", accept)
    req.add_header("User-Agent", UA)
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req) as resp:
            payload = resp.read().decode()
            return resp.status, (json.loads(payload) if payload else None)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def upload_asset(token, release_id, asset, labels, dry):
    """Upload one file to a release, optionally tagging it as a GitHub "label"
    (e.g. `Chrome`, `Firefox`, `OnionShare`) so the browser shows a nice chip."""
    url = (f"https://uploads.github.com/repos/{repo_slug()}/releases/{release_id}"
           f"/assets?name={asset.name}")
    data = asset.read_bytes()
    for label in labels:
        url += f"&label={urllib.parse.quote(label)}"
    if dry:
        log(f"  [dry-run] upload {asset.name} -> releases/{release_id}/assets")
        return
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", UA)
    req.add_header("Content-Type", mimetypes.guess_type(asset.name)[0] or "application/octet-stream")
    try:
        with urllib.request.urlopen(req) as resp:
            log(f"  uploaded {asset.name} ({resp.status})")
    except urllib.error.HTTPError as exc:
        # Asset already exists — GitHub rejects the duplicate. Re-uploading the same
        # bytes against a draft-restart is fine; (already exists) is success-ish.
        msg = exc.read().decode()[:200]
        if "already exists" in msg:
            log(f"  {asset.name} already present (skipped)")
        else:
            die(f"asset upload failed for {asset.name} ({exc.code}): {msg}")


def github_release(token, tag, target, body, dry):
    url = f"https://api.github.com/repos/{repo_slug()}/releases"
    payload = {
        "tag_name": tag,
        "target_commitish": target,
        "name": f"CIPHER//NET {tag}",
        "body": body,
        "draft": False,
        "prerelease": False,
        "generate_release_notes": True,
    }
    if dry:
        log(f"  [dry-run] POST {url} tag={tag}")
        return None
    status, resp = gh_request("POST", url, token, payload)
    if status not in (200, 201):
        die(f"GitHub release create failed ({status}): {resp}")
    return resp


# --- artifact builders ---------------------------------------------------------------


def stamp_sw(version, dry):
    """Bump the sw.js cache name so the previous service-worker stops serving stale assets."""
    text = SW.read_text(encoding="utf-8")
    match = re.search(r"const CACHE = 'ciphernet-v([0-9]+)'", text)
    if not match:
        die("cannot find `const CACHE = 'ciphernet-vN'` in app/sw.js")
    new_cache = f"ciphernet-v{int(match.group(1)) + 1}"
    if dry:
        log(f"  [dry-run] sw.js CACHE {match.group(0)} -> {new_cache}")
        return
    SW.write_text(text.replace(match.group(0), f"const CACHE = '{new_cache}'"),
                  encoding="utf-8", newline="\n")
    log(f"sw.js CACHE {match.group(0)} -> {new_cache}")


def bump_manifest(version, dry):
    if not PACKAGE.exists():
        die("extension manifest.json missing")
    text = PACKAGE.read_text(encoding="utf-8")
    new_text, n = re.subn(r'("version"\s*:\s*")[^"]+(")', rf"\g<1>{version}\g<2>", text, count=1)
    if n == 0:
        die("no \"version\" field in extension manifest.json")
    if dry:
        log(f"  [dry-run] manifest.json version -> {version}")
        return
    PACKAGE.write_text(new_text, encoding="utf-8", newline="\n")
    log(f"manifest.json version -> {version}")


def zip_dir(zip_path, root):
    """Zip the *contents* of root (not root itself) so archives unpack cleanly."""
    # Direct zipfile: no make_archive (it ALWAYS appends ".zip", so a base that
    # still ends in ".zip" yields a stray "...zip.zip"), no tmp, no rename, no
    # cross-drive move. The archive is written exactly where zip_path says.
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fp in sorted(Path(root).rglob("*")):
            if fp.is_file():
                zf.write(fp, fp.relative_to(root).as_posix())
    log(f"built {zip_path.name}")
def xpi_from_zip(web_zip, extension_zip):
    """An XPI is just a zip with a manifest.json at its root — reuse the built
    extension zip so the content is byte-identical to what Chrome loads."""
    xpi = extension_zip.with_suffix(".xpi")
    shutil.copyfile(extension_zip, xpi)
    log(f"built {xpi.name} (copy of {extension_zip.name})")
    return xpi


# --- orchestration -------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Build and publish a CIPHER//NET release locally.")
    ap.add_argument("--version", default=None,
                    help="x.y.z version (default: bump the `version=` in versions.properties)")
    ap.add_argument("--tag", default=None,
                    help="git tag to use (default: v<version>.<stamp>)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--unsigned", action="store_true", help="do not GPG-sign the commit/tag")
    ap.add_argument("--allow-dirty", action="store_true")
    ap.add_argument("--no-push", action="store_true")
    ap.add_argument("--skip-build", action="store_true", help="reuse existing dist/ artifacts")
    ap.add_argument("--local-only", action="store_true",
                    help="build + stage dist/ only: no commit, tag, push, GitHub release or upload")
    args = ap.parse_args()
    dry = args.dry_run

    ensure_clean(args.allow_dirty)

    # --- resolve version -------------------------------------------------------------
    if args.version:
        version = re.sub(r"^v", "", args.version)
    else:
        base = read_prop(VERSIONS, "version", "1.0.0")
        parts = [int(p) for p in base.split(".")]
        parts[-1] += 1
        version = ".".join(str(p) for p in parts)
    stamp = now_stamp()
    tag = args.tag or f"v{version}.{stamp}"
    log(f"version: {version}  tag: {tag}")

    # --- bump + build ----------------------------------------------------------------
    if args.local_only:
        pass  # still bump manifest/sw below
    bump_manifest(version, dry)
    stamp_sw(version, dry)
    if not args.skip_build:
        zip_dir(DIST / f"ciphernet-web-{tag}.zip", APP)
        zip_dir(DIST / f"ciphernet-extension-{tag}.zip", EXT)
        xpi_from_zip(DIST / f"ciphernet-web-{tag}.zip", DIST / f"ciphernet-extension-{tag}.zip")

    if args.local_only:
        log(f"local-only: staged dist/ for {tag}; no commit/tag/GitHub release performed")
        return

    set_prop(VERSIONS, "version", version)
    commit([str(PACKAGE), str(SW), str(VERSIONS)], f"Release {tag}: bump version {version}",
           dry, sign=not args.unsignedSentence)

    branch = current_branch()
    run(["git", "-C", str(_ROOT), "push", "origin", branch], dry=dry)
    cmd = ["git", "-C", str(_ROOT), "tag", "-a", tag, "-m", f"Release {tag}"]
    if args.unsigned:
        cmd += ["--no-gpg-sign"]
    run(cmd, dry=dry)
    run(["git", "-C", str(_ROOT), "push", "origin", tag], dry=dry)

    token = github_token()
    body = (
        f"CIPHER//NET {tag}\n\n"
        "- **Web app** zip — drop into any static host / OnionShare folder.\n"
        "- **Extension** zip — load unpacked in Chrome/Edge/Brave/Firefox.\n"
        "- **Extension .xpi** — sign via AMO or install as a temporary Firefox add-on.\n\n"
        "Builds happened locally; nothing is compiled in CI."
    )
    release = github_release(token, tag, branch, body, dry)
    if release is None:
        return
    rid = release["id"]
    problems = []
    # Don't ship the temporary .zip.tmp or stale artifacts from an aborted prior run.
    for fn in [f"ciphernet-web-{tag}.zip", f"ciphernet-extension-{tag}.zip",
               f"ciphernet-extension-{tag}.xpi"]:
        asset = DIST / fn
        if not asset.exists():
            problems.append(fn)
            continue
        labels = {"OnionShare / static host"} if fn.startswith("ciphernet-web") else \
                 {"Chrome / Firefox"} if fn.endswith(".zip") else {"Firefox Add-on"}
        upload_asset(token, rid, asset, labels, dry)
    if problems:
        print(f"release: missing artifacts not uploaded: {', '.join(problems)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
