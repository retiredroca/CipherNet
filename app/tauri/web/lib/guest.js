window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const Crypto = window.CipherNet.Crypto;
  const Bip39  = window.CipherNet.Bip39;
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;
  const VALID_HANDLE = window.CipherNet.Util.VALID_HANDLE;
  const { state, getStoredUsers } = window.CipherNet.State;
  const Render = window.CipherNet.Render;
  const LockScreen = window.CipherNet.LockScreen;

  const PACK_KEY = 'cipher_identity_pack';
  const SKIP_KEY = 'cipher_guest_skip';

  let _pendingPhrase = null;

  function isGuest() { return !!(state.me && state.me.guest); }
  function hasIdentityPack() { return !!localStorage.getItem(PACK_KEY); }

  function buildGuestIdentity() {
    return (async () => {
      let pq = false;
      try { pq = Crypto.pqAvailable() && !!window.ml_dsa65 && !!window.ml_kem768; } catch { pq = false; }

      let algo, signingKey, publicKey, dhPrivKey, dhPubKey;
      if (pq) {
        const signing = await Crypto.generateMLDSAKeypair();
        const kem     = await Crypto.generateMLKEMKeypair();
        algo        = { name: 'ML-DSA-65' };
        signingKey  = signing.secretKey;
        publicKey   = Crypto.bytesToB64(signing.publicKey);
        dhPrivKey   = kem.secretKey;
        dhPubKey    = Crypto.bytesToB64(kem.publicKey);
      } else {
        const keys = await Crypto.generateECDSA('P-256');
        const dh   = await Crypto.generateDHKeypair();
        algo       = { name: 'ECDSA', namedCurve: 'P-256' };
        signingKey = keys.privateKey;
        publicKey  = await Crypto.exportPubPem(keys.publicKey);
        dhPrivKey  = dh.privateKey;
        dhPubKey   = await Crypto.exportPubPem(dh.publicKey);
      }

      const fp     = await Crypto.fingerprint(publicKey);
      const handle = 'guest_' + fp.slice(0, 8);
      return { handle, publicKeyPem: publicKey, signingKey, fingerprint: fp, algo, dhPrivKey, dhPubKeyPem: dhPubKey, guest: true };
    })();
  }

  async function enterAsGuest() {
    try {
      const me = await buildGuestIdentity();
      sessionStorage.removeItem(SKIP_KEY);
      state.me = me;
      LockScreen.enterApp();
      const sw = $('storage-warning');
      if (sw) sw.classList.add('hidden');
      updateGuestBanner(true);
      $('auth-btn').textContent = '[ ' + me.handle.toUpperCase() + ' // GUEST ]';
      Render.sysMsg(me.handle + ' entered as temporary guest.');
      toast('Temporary guest session \u2014 nothing saved. Use Persist Identity to keep it.');
    } catch (e) {
      toast('Could not create guest identity: ' + e.message);
    }
  }

  function continueAsGuest() {
    sessionStorage.removeItem(SKIP_KEY);
    enterAsGuest();
  }

  function useExistingKey() {
    if (confirm('Switch to an existing key? Your guest session will be discarded.')) {
      sessionStorage.setItem(SKIP_KEY, '1');
      location.reload();
    }
  }

  function updateGuestBanner(show) {
    const b = $('guest-banner');
    if (b) b.classList.toggle('hidden', !show);
  }

  // ── Lock screen unlock flow ─────────────────────────────

  function switchUnlockPanel() {
    ['register', 'login', 'unlock'].forEach(n => {
      const t = $('lock-tab-' + n);
      const p = $('lock-panel-' + n);
      if (t) t.classList.toggle('active', n === 'unlock');
      if (p) p.classList.toggle('hidden', n !== 'unlock');
    });
  }

  function showUnlock() {
    const tab = $('lock-tab-unlock');
    if (tab) tab.classList.remove('hidden');
    switchUnlockPanel();
  }

  async function unlockIdentity() {
    const phrase = ($('unlock-phrase') && $('unlock-phrase').value.trim().toLowerCase()) || '';
    const err    = $('unlock-error');
    err.classList.add('hidden');
    if (!phrase) { err.textContent = 'Enter your recovery phrase.'; err.classList.remove('hidden'); return; }
    if (!(await Bip39.validateMnemonic(phrase))) {
      err.textContent = 'That is not a valid 24-word recovery phrase. Check the word list and spelling.';
      err.classList.remove('hidden');
      return;
    }
    const btn  = $('btn-unlock');
    const orig = btn.textContent;
    btn.disabled = true; btn.textContent = 'UNLOCKING...';
    try {
      const encStr = localStorage.getItem(PACK_KEY);
      if (!encStr) throw new Error('No saved identity found in this browser');
      const bytes = await Crypto.decryptIdentityPack(encStr, phrase);
      const pack  = JSON.parse(new TextDecoder().decode(bytes));
      await restoreFromPack(pack);
      sessionStorage.removeItem(SKIP_KEY);
      const users = getStoredUsers();
      users[state.me.fingerprint] = {
        handle: state.me.handle, publicKeyPem: state.me.publicKeyPem,
        fingerprint: state.me.fingerprint, algo: state.me.algo,
        dhPubKeyPem: state.me.dhPubKeyPem || null,
      };
      localStorage.setItem('cipher_users', JSON.stringify(users));
      localStorage.setItem('cipher_my_fingerprint', state.me.fingerprint);
      $('unlock-phrase').value = '';
      LockScreen.enterApp();
      Render.sysMsg('Identity restored from recovery phrase.');
      toast('Welcome back ' + state.me.handle);
    } catch (e) {
      err.textContent = e.message || 'Unlock failed';
      err.classList.remove('hidden');
      $('unlock-phrase').value = '';
    }
    btn.disabled = false; btn.textContent = orig;
  }

  // `me.algo` is stored as { name: 'ECDSA', namedCurve: 'P-256'|'P-384' } (no
  // suffix); older packs used the suffixed names. Accept both.
  const VALID_PACK_ALGO = { 'ML-DSA-65': true, 'ECDSA': true, 'ECDSA-P256': true, 'ECDSA-P384': true, 'RSA-PSS': true };
  const HEX_FP = /^[0-9a-fA-F]{16}$/;

  async function restoreFromPack(pack) {
    if (!pack || typeof pack !== 'object') throw new Error('Malformed identity pack');
    if (!pack.fp || !HEX_FP.test(pack.fp)) throw new Error('Identity pack missing fingerprint');
    if (!pack.algo || !VALID_PACK_ALGO[pack.algo.name]) throw new Error('Identity pack has an unknown algorithm');
    if (typeof pack.handle !== 'string') throw new Error('Identity pack missing handle');

    const algo = { name: pack.algo.name };
    if (pack.algo.name === 'ECDSA') algo.namedCurve = pack.algo.namedCurve || 'P-256';
    if (pack.algo.name === 'RSA-PSS') algo.hash = 'SHA-256';
    if (pack.algo.name === 'ECDSA' && algo.namedCurve !== 'P-256' && algo.namedCurve !== 'P-384') {
      throw new Error('Identity pack has an unsupported curve');
    }

    let signingKey, dhPrivKey;
    if (pack.algo.name === 'ML-DSA-65') {
      if (typeof pack.signingKey !== 'string' || typeof pack.dhPrivKey !== 'string') throw new Error('Identity pack missing key material');
      signingKey = Crypto.decodePQSecretKey(pack.signingKey);
      dhPrivKey  = Crypto.b64ToBytes(pack.dhPrivKey);
    } else {
      if (typeof pack.signingKey !== 'string' || typeof pack.dhPrivKey !== 'string') throw new Error('Identity pack missing key material');
      const sig = await Crypto.importPrivateKey(pack.signingKey);
      signingKey = sig.privateKey;
      dhPrivKey  = await crypto.subtle.importKey(
        'pkcs8', Crypto.fromPem(pack.dhPrivKey),
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
      );
    }

    state.me = {
      handle: pack.handle, publicKeyPem: pack.publicKeyPem, signingKey,
      fingerprint: pack.fp, algo,
      dhPrivKey, dhPubKeyPem: pack.dhPubKeyPem || null,
    };
  }

  // ── Persist flow ─────────────────────────────────────────

  async function openPersistModal() {
    if (!state.me) { toast('Sign in first'); return; }
    _pendingPhrase = await Bip39.generateMnemonic();
    $('persist-phrase').textContent = _pendingPhrase;
    $('persist-name').value = state.me.handle;
    $('persist-confirm').checked = false;
    $('persist-error').classList.add('hidden');
    $('persist-modal').classList.remove('hidden');
  }

  function closePersistModal() {
    $('persist-modal').classList.add('hidden');
    _pendingPhrase = null;
  }

  async function buildIdentityPack() {
    const me  = state.me;
    const pack = {
      v: 1, type: 'cipher-identity-pack',
      handle: me.handle, fp: me.fingerprint, algo: me.algo,
      publicKeyPem: me.publicKeyPem, dhPubKeyPem: me.dhPubKeyPem,
      createdAt: Date.now(),
    };
    if (me.algo.name === 'ML-DSA-65') {
      pack.signingKey = Crypto.encodePQSecretKey(me.signingKey);
      pack.dhPrivKey  = Crypto.bytesToB64(me.dhPrivKey);
    } else {
      pack.signingKey = await Crypto.exportPrivPem(me.signingKey);
      pack.dhPrivKey  = await Crypto.exportPrivPem(me.dhPrivKey);
    }
    return pack;
  }

  async function persistIdentity() {
    if (!_pendingPhrase) { showPersistError('No recovery phrase generated. Cancel and reopen.'); return; }
    if (!$('persist-confirm').checked) { showPersistError('Confirm that you saved your recovery phrase securely.'); return; }
    const nameEl = $('persist-name');
    const name   = nameEl ? nameEl.value.trim() : '';
    if (name && !VALID_HANDLE.test(name)) { showPersistError('Handle: 3-32 chars, letters/numbers/underscores.'); return; }

    const btn  = $('persist-save');
    const orig = btn.textContent;
    btn.disabled = true; btn.textContent = 'ENCRYPTING...';
    try {
      const pack = await buildIdentityPack();
      if (name) pack.handle = name;
      const enc  = await Crypto.encryptIdentityPack(_pendingPhrase, new TextEncoder().encode(JSON.stringify(pack)));
      localStorage.setItem(PACK_KEY, enc);
      if (name) setDisplayName(name);
      closePersistModal();
      toast('Identity saved. Return anytime with your 24-word recovery phrase.');
    } catch (e) {
      showPersistError(e.message || 'Could not save identity');
    }
    btn.disabled = false; btn.textContent = orig;
  }

  function showPersistError(msg) {
    const el = $('persist-error');
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  function copyPendingPhrase() {
    if (!_pendingPhrase) return;
    navigator.clipboard.writeText(_pendingPhrase)
      .then(() => toast('Recovery phrase copied'))
      .catch(() => toast('Copy failed \u2014 select the phrase manually'));
  }

  // ── Display name ─────────────────────────────────────────

  function setDisplayName(name) {
    const s = String(name || '').trim();
    if (!VALID_HANDLE.test(s)) { toast('Handle: 3-32 chars, letters/numbers/underscores'); return false; }
    state.me.handle = s;
    const myFp = localStorage.getItem('cipher_my_fingerprint');
    if (myFp && state.me.fingerprint === myFp) {
      const users = getStoredUsers();
      if (users[state.me.fingerprint]) {
        users[state.me.fingerprint].handle = s;
        localStorage.setItem('cipher_users', JSON.stringify(users));
      }
    }
    Render.updateMsgInput();
    Render.updateUserBadge();
    $('auth-btn').textContent = '[ ' + s.toUpperCase() + (isGuest() ? ' // GUEST' : '') + ' ]';
    toast('Display name set to ' + s);
    return true;
  }

  function promptDisplayName() {
    if (!state.me) { toast('Sign in first'); return; }
    const name = prompt('New display name (3-32 chars, letters/numbers/_):', state.me.handle || '');
    if (name === null) return;
    setDisplayName(name.trim());
  }

  document.addEventListener('DOMContentLoaded', function initGuest() {
    const tabUnlock = $('lock-tab-unlock');
    if (tabUnlock) tabUnlock.addEventListener('click', switchUnlockPanel);
    const btnUnlock = $('btn-unlock');
    if (btnUnlock) btnUnlock.addEventListener('click', unlockIdentity);
    const btnGuest = $('btn-guest-continue');
    if (btnGuest) btnGuest.addEventListener('click', continueAsGuest);
    const gbExisting = $('gb-existing');
    if (gbExisting) gbExisting.addEventListener('click', useExistingKey);
    const gbExport = $('gb-export');
    if (gbExport) gbExport.addEventListener('click', () => {
      if (window.CipherNet.Identity) window.CipherNet.Identity.exportIdentity();
    });
    const gbDisplay = $('gb-display-name');
    if (gbDisplay) gbDisplay.addEventListener('click', promptDisplayName);
    const gbPersist = $('gb-persist');
    if (gbPersist) gbPersist.addEventListener('click', openPersistModal);

    $('persist-cancel') && $('persist-cancel').addEventListener('click', closePersistModal);
    $('persist-save')   && $('persist-save').addEventListener('click', persistIdentity);
    $('persist-copy')   && $('persist-copy').addEventListener('click', copyPendingPhrase);
    $('persist-modal')  && $('persist-modal').addEventListener('click', e => {
      if (e.target === $('persist-modal')) closePersistModal();
    });
  });

  window.CipherNet.Guest = {
    isGuest, hasIdentityPack,
    enterAsGuest, continueAsGuest, useExistingKey, buildGuestIdentity,
    showUnlock, unlockIdentity, restoreFromPack,
    openPersistModal, closePersistModal, persistIdentity, copyPendingPhrase,
    setDisplayName, promptDisplayName, updateGuestBanner,
  };
})();