window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;
  const showStorageWarning = window.CipherNet.Util.showStorageWarning;
  const dismissStorageWarning = window.CipherNet.Util.dismissStorageWarning;
  const handleDragOver = window.CipherNet.Util.handleDragOver;
  const handleDragLeave = window.CipherNet.Util.handleDragLeave;
  const handleDrop = window.CipherNet.Util.handleDrop;
  const Crypto = window.CipherNet.Crypto;
  const { getStoredUsers } = window.CipherNet.State;
  const LockScreen = window.CipherNet.LockScreen;
  const Messaging = window.CipherNet.Messaging;
  const Identity = window.CipherNet.Identity;

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('./sw.js')
        .catch(err => console.warn('SW registration failed:', err));
    });
  }

  document.addEventListener('DOMContentLoaded', () => {

    if (window.__CIPHERNET_DESKTOP__ && window.__TAURI_INTERNALS__) {
      import('https://unpkg.com/@tauri-apps/api@2/core').then(({ invoke }) => {
        invoke('get_tor_proxy').then(proxy => {
          window.__CIPHERNET_TOR_PROXY__ = proxy;
          if (proxy) console.log('[CIPHER//NET] Tauri: Tor proxy detected:', proxy);
        }).catch(() => {});
      }).catch(() => {});
    }

    setTimeout(function() {
      if (window.ml_dsa65 && window.ml_kem768) {
        console.log('[CIPHER//NET] \u269b PQ ready \u2014 ml_dsa65 and ml_kem768 available');
      } else {
        console.warn('[CIPHER//NET] PQ not loaded \u2014 noble-post-quantum.js missing or failed. Classical algorithms still work.');
      }
    }, 500);

    if (!window.crypto || !window.crypto.subtle) {
      document.body.innerHTML = '<div class="no-crypto">Web Crypto API unavailable. Use HTTPS, .onion, or localhost.</div>';
      return;
    }

    $('lock-tab-register').addEventListener('click', () => LockScreen.switchLockTab('register'));
    $('lock-tab-login').addEventListener('click',    () => LockScreen.switchLockTab('login'));

    $('reg-algo').addEventListener('change', function() {
      const hints = {
        'ML-DSA-65':  '\u269b ML-DSA-65 + ML-KEM-768 \u2014 FIPS 203/204 post-quantum. Resistant to quantum computers. Keys are larger than classical.',
        'ECDSA-P256': 'ECDSA P-256 + ECDH P-256 \u2014 classical elliptic curve. Fast, widely supported. Not quantum-resistant.',
        'ECDSA-P384': 'ECDSA P-384 + ECDH P-256 \u2014 classical. Stronger curve, slightly slower.',
        'RSA-PSS':    'RSA-PSS 2048 + ECDH P-256 \u2014 classical RSA. Large keys, slowest generation.',
      };
      const h = $('algo-hint');
      if (h) h.textContent = hints[this.value] || '';
      const note = $('pq-key-note');
      if (note) note.classList.toggle('hidden', this.value !== 'ML-DSA-65');
    });

    $('btn-gen').addEventListener('click', LockScreen.generateKeys);
    $('btn-activate').addEventListener('click', LockScreen.activateAccount);
    $('copy-priv-btn').addEventListener('click', () => Messaging.copyKey('priv'));
    $('copy-pub-btn').addEventListener('click',  () => Messaging.copyKey('pub'));
    $('btn-import').addEventListener('click', LockScreen.importKey);

    $('login-privkey').addEventListener('input', function() {
      const pg = $('import-password-group');
      if (!pg) return;
      if (Crypto.isEncryptedKey(this.value)) {
        pg.style.display = '';
        pg.classList.remove('hidden');
        $('import-password-hint').textContent = '\u2014 encrypted key detected, password required';
        $('import-password-hint').style.color = 'var(--amber)';
      } else {
        pg.style.display = 'none';
      }
    });

    const dz = $('drop-zone');
    dz.addEventListener('click',     () => $('identity-file-input').click());
    dz.addEventListener('dragover',  handleDragOver);
    dz.addEventListener('dragleave', handleDragLeave);
    dz.addEventListener('drop',      handleDrop);
    $('identity-file-input').addEventListener('change', e => {
      if (e.target.files[0]) Identity.readIdentityFile(e.target.files[0]);
    });

    $('auth-btn').addEventListener('click', () => {
      if (confirm('Sign out? You will need your private key to sign back in.')) location.reload();
    });
    $('warn-export-btn').addEventListener('click', Identity.exportIdentity);
    $('dismiss-warn-btn').addEventListener('click', dismissStorageWarning);
    $('btn-export-identity').addEventListener('click', Identity.exportIdentity);
    $('btn-export-backup').addEventListener('click', Identity.exportFullBackup);

    $('btn-channel-manager') && $('btn-channel-manager').addEventListener('click', () => {
      if (window.CipherNet.ChannelUI) window.CipherNet.ChannelUI.openChannelModal();
    });

    $('msg-input').addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); Messaging.sendMessage(); }
    });
    $('btn-send').addEventListener('click', Messaging.sendMessage);

    $('btn-set-passphrase').addEventListener('click', Messaging.setChannelPassphrase);
    $('channel-passphrase').addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); Messaging.setChannelPassphrase(); }
    });

    $('dm-modal-cancel').addEventListener('click', () => window.CipherNet.Util.closeDMModal());
    $('dm-modal-confirm').addEventListener('click', Messaging.confirmDMKeyExchange);

    const myFp  = localStorage.getItem('cipher_my_fingerprint');
    const users = getStoredUsers();
    if (myFp && users[myFp]) {
      LockScreen.switchLockTab('login');
      $('login-username').value = users[myFp].handle;
      toast('Welcome back ' + users[myFp].handle + ' - paste your private key');
    }
  });

  window.CipherNet.Boot = {};
})();
