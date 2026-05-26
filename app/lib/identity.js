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
      if (raw) dms[fp] = JSON.parse(raw);
    });
    downloadJSON({
      cipher_version: 1, type: 'full_backup',
      myFingerprint: state.me.fingerprint,
      exportedAt: new Date().toISOString(), users, channels, dms,
      note: 'Encrypted ciphertext + public keys. Private signing key NOT included \u2014 paste it on import.',
    }, 'cipher-backup-' + state.me.handle + '-' + Date.now() + '.json');
    toast('Full backup exported');
  }

  function readIdentityFile(file) {
    const r = new FileReader();
    r.onload = e => {
      try { applyIdentityFile(JSON.parse(e.target.result)); }
      catch { showLoginError('Invalid JSON file.'); }
    };
    r.readAsText(file);
  }

  function applyIdentityFile(data) {
    if (!data.cipher_version) { showLoginError('Not a CIPHER//NET file.'); return; }

    window.CipherNet.LockScreen.switchLockTab('login');

    if (data.type === 'full_backup') {
      if (data.users)
        localStorage.setItem('cipher_users', JSON.stringify({ ...getStoredUsers(), ...data.users }));
      if (data.channels)
        for (const [ch, msgs] of Object.entries(data.channels))
          if (Array.isArray(msgs) && msgs.length)
            localStorage.setItem('cipher_msgs_' + ch, JSON.stringify(msgs));
      if (data.dms)
        for (const [fp, msgs] of Object.entries(data.dms)) {
          const key = window.CipherNet.Messaging.dmStorageKey(data.myFingerprint, fp);
          if (Array.isArray(msgs) && msgs.length)
            localStorage.setItem(key, JSON.stringify(msgs));
        }
      const handle = data.myFingerprint && data.users?.[data.myFingerprint]?.handle;
      if (handle) $('login-username').value = handle;
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
