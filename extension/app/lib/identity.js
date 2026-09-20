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
window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;
  const downloadJSON = window.CipherNet.Util.downloadJSON;
  const showLoginError = window.CipherNet.Util.showLoginError;
  const showStorageWarning = window.CipherNet.Util.showStorageWarning;
  const scrollToBottom = window.CipherNet.Util.scrollToBottom;
  const { state, getStoredUsers } = window.CipherNet.State;

  function exportIdentity() {
    if (!state.me) { toast('Sign in first'); return; }
    downloadJSON({
      cipher_version: 1, type: 'public_identity',
      handle: state.me.handle, fingerprint: state.me.fingerprint,
      publicKeyPem: state.me.publicKeyPem, algo: state.me.algo,
      dhPubKeyPem: state.me.dhPubKeyPem,
      exportedAt: new Date().toISOString(),
      note: 'Public keys only \u2014 safe to share. Includes DM public key for ECDH key exchange.',
    }, 'cipher-identity-' + state.me.handle + '.json');
    toast('Public identity exported');
  }

  function exportFullBackup() {
    if (!state.me) { toast('Sign in first'); return; }
    const users    = getStoredUsers();
    const channels = ['general','random','tech'].reduce((acc, ch) => {
      try { acc[ch] = JSON.parse(localStorage.getItem('cipher_msgs_' + ch) || '[]'); } catch {}
      return acc;
    }, {});
    const dms = {};
    Object.keys(users).forEach(fp => {
      if (fp === state.me.fingerprint) return;
      const key = window.CipherNet.Messaging.dmStorageKey(state.me.fingerprint, fp);
      const raw = localStorage.getItem(key);
      if (!raw) return;
      try { dms[fp] = JSON.parse(raw); }
      catch { /* unreadable DM log for this peer — skip */ }
    });
    downloadJSON({
      cipher_version: 1, type: 'full_backup',
      myFingerprint: state.me.fingerprint,
      exportedAt: new Date().toISOString(), users, channels, dms,
      note: 'Encrypted ciphertext + public keys. Private signing key NOT included \u2014 paste it on import.',
    }, 'cipher-backup-' + state.me.handle + '-' + Date.now() + '.json');
    toast('Full backup exported');
  }

  const MAX_IDENTITY_FILE_BYTES = 5 * 1024 * 1024;

  function readIdentityFile(file) {
    if (file && file.size > MAX_IDENTITY_FILE_BYTES) {
      showLoginError('File too large (max 5 MB).');
      return;
    }
    const r = new FileReader();
    r.onload = e => {
      try { applyIdentityFile(JSON.parse(e.target.result)); }
      catch { showLoginError('Invalid JSON file.'); }
    };
    r.readAsText(file);
  }

  const VALID_ALGOS = { 'ML-DSA-65': true, 'ECDSA-P256': true, 'ECDSA-P384': true, 'RSA-PSS': true };
  const HEX_FP = /^[0-9a-fA-F]{16}$/;

  function sanitizeIdentity(data) {
    const out = { type: data.type, cipher_version: Number(data.cipher_version) || 0 };
    if (data.handle) out.handle = window.CipherNet.Util.sanitizeHandle(data.handle, data.fingerprint);
    if (typeof data.fingerprint === 'string' && HEX_FP.test(data.fingerprint)) out.fingerprint = data.fingerprint.toLowerCase();
    if (typeof data.myFingerprint === 'string' && HEX_FP.test(data.myFingerprint)) out.myFingerprint = data.myFingerprint.toLowerCase();
    if (typeof data.publicKeyPem === 'string' && data.publicKeyPem.length > 0) out.publicKeyPem = data.publicKeyPem;
    if (data.dhPubKeyPem) {
      if (typeof data.dhPubKeyPem === 'string' && data.dhPubKeyPem.length > 0) out.dhPubKeyPem = data.dhPubKeyPem;
      else out.dhPubKeyPem = null;
    }
    if (data.algo && typeof data.algo === 'object') {
      const name = data.algo.name;
      const a = { name };
      if (name === 'ECDSA') a.namedCurve = data.algo.namedCurve || 'P-256';
      if (name === 'RSA-PSS') a.hash = 'SHA-256';
      if (VALID_ALGOS[name]) out.algo = a;
    }
    return out;
  }

  function applyIdentityFile(raw) {
    if (!raw.cipher_version) { showLoginError('Not a CIPHER//NET file.'); return; }
    const data = sanitizeIdentity(raw);

    window.CipherNet.LockScreen.switchLockTab('login');

    if (data.type === 'full_backup') {
      const users = data.users;
      if (!users || typeof users !== 'object') { showLoginError('Backup missing user registry.'); return; }
      for (const [fp, u] of Object.entries(users) || {}) {
        if (!u || typeof u !== 'object') continue;
        u.handle = window.CipherNet.Util.sanitizeHandle(u.handle, u.fingerprint);
        if (!HEX_FP.test(u.fingerprint || '')) continue;
        if (typeof u.publicKeyPem !== 'string' || !u.publicKeyPem) continue;
        if (u.algo && u.algo.name && !VALID_ALGOS[u.algo.name]) delete u.algo;
      }
      if (data.users)
        localStorage.setItem('cipher_users', JSON.stringify({ ...getStoredUsers(), ...users }));
      if (data.channels && typeof data.channels === 'object')
        for (const [ch, msgs] of Object.entries(data.channels))
          if (Array.isArray(msgs) && msgs.length && typeof ch === 'string')
            localStorage.setItem('cipher_msgs_' + ch, JSON.stringify(msgs));
      if (data.dms && typeof data.dms === 'object')
        for (const [fp, msgs] of Object.entries(data.dms)) {
          if (!HEX_FP.test(fp)) continue;
          const key = window.CipherNet.Messaging.dmStorageKey(data.myFingerprint, fp);
          if (Array.isArray(msgs) && msgs.length && typeof key === 'string')
            localStorage.setItem(key, JSON.stringify(msgs));
        }
      const handle = data.myFingerprint && data.users?.[data.myFingerprint]?.handle;
      if (handle) $('login-username').value = window.CipherNet.Util.sanitizeHandle(handle, data.myFingerprint);
      showIdentityPreview({ type: 'full_backup', userCount: Object.keys(data.users || {}).length });
      toast('Backup restored \u2014 paste your private key below');
      return;
    }

    if (data.handle) $('login-username').value = data.handle;
    if (data.fingerprint && data.publicKeyPem) {
      const users = getStoredUsers();
      users[data.fingerprint] = {
        handle: data.handle, publicKeyPem: data.publicKeyPem,
        fingerprint: data.fingerprint, algo: data.algo,
        dhPubKeyPem: data.dhPubKeyPem || null,
      };
      localStorage.setItem('cipher_users', JSON.stringify(users));
    }
    showIdentityPreview(data);
    toast('Identity loaded \u2014 paste your private key below');
  }

  function showIdentityPreview(data) {
    const el = $('identity-preview');
    el.classList.remove('hidden'); el.innerHTML = '';
    const lbl = document.createElement('div'); lbl.className = 'ip-label';
    lbl.textContent = data.type === 'full_backup' ? '// BACKUP RESTORED' : '// IDENTITY FILE LOADED';
    el.appendChild(lbl);
    const lines = data.type === 'full_backup'
      ? [data.userCount + ' user(s) restored. Paste your private key below.']
      : ['Handle: ' + (data.handle||'?'), 'Fingerprint: ' + (data.fingerprint||'?'),
         'DM key: ' + (data.dhPubKeyPem ? 'present' : 'not in file'),
         'Paste your private key below.'];
    lines.forEach(t => { const d = document.createElement('div'); d.textContent = t; el.appendChild(d); });
  }

  window.CipherNet.Identity = {
    exportIdentity, exportFullBackup,
    readIdentityFile, applyIdentityFile, showIdentityPreview,
  };
})();
