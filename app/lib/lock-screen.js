window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const Crypto = window.CipherNet.Crypto;
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;
  const showLoginError = window.CipherNet.Util.showLoginError;
  const hideLoginError = window.CipherNet.Util.hideLoginError;
  const { state, getStoredUsers } = window.CipherNet.State;
  const Render = window.CipherNet.Render;
  const Messaging = window.CipherNet.Messaging;

  async function generateKeys() {
    const username = $('reg-username').value.trim();
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) { toast('Handle: 3-32 chars, letters/numbers/underscores'); return; }

    const algo = $('reg-algo').value;
    const btn  = $('btn-gen');
    btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>GENERATING...';
    $('key-gen-area').classList.remove('hidden');
    animateProgress(0, 35, 500);

    let keys, privPem, pubPem, dhPubPem;
    const isPQ = (algo === 'ML-DSA-65');

    try {
      if (isPQ) {
        btn.innerHTML = '<span class="spinner"></span>LOADING PQ LIB...';
        const pqReady = await new Promise(resolve => {
          if (window._pqLoaded) { resolve(true); return; }
          let waited = 0;
          const interval = setInterval(() => {
            waited += 100;
            if (window._pqLoaded) { clearInterval(interval); resolve(true); }
            else if (waited >= 3000) { clearInterval(interval); resolve(false); }
          }, 100);
        });
        if (!pqReady) {
          const err = window._pqError
            ? 'PQ load error: ' + window._pqError
            : 'noble-post-quantum.js not found. Make sure the file is in the same folder as index.html and is committed to your repo. Select a classical algorithm to continue without PQ.';
          toast(err);
          btn.disabled = false; btn.innerHTML = 'GENERATE KEYPAIR'; return;
        }
        btn.innerHTML = '<span class="spinner"></span>GENERATING...';

        const note = $('pq-key-note');
        if (note) note.classList.remove('hidden');

        keys = await Crypto.generateMLDSAKeypair();
        animateProgress(35, 65, 400);
        const kemKeys = await Crypto.generateMLKEMKeypair();
        animateProgress(65, 90, 300);

        privPem  = Crypto.encodePQSecretKey(keys.secretKey);
        pubPem   = Crypto.bytesToB64(keys.publicKey);
        dhPubPem = Crypto.bytesToB64(kemKeys.publicKey);

        state.generatedCryptoKeys = keys;
        state.generatedDHKeys     = kemKeys;
        state.generatedAlgo       = { name: 'ML-DSA-65' };
      } else {
        if      (algo === 'ECDSA-P256') keys = await Crypto.generateECDSA('P-256');
        else if (algo === 'ECDSA-P384') keys = await Crypto.generateECDSA('P-384');
        else                            keys = await Crypto.generateRSAPSS();
        animateProgress(35, 65, 400);
        const dhKeys = await Crypto.generateDHKeypair();
        animateProgress(65, 90, 300);

        privPem  = await Crypto.exportPrivPem(keys.privateKey);
        pubPem   = await Crypto.exportPubPem(keys.publicKey);
        dhPubPem = await Crypto.exportPubPem(dhKeys.publicKey);

        state.generatedCryptoKeys = keys;
        state.generatedDHKeys     = dhKeys;
        state.generatedAlgo = algo === 'ECDSA-P256' ? { name: 'ECDSA', namedCurve: 'P-256' }
                            : algo === 'ECDSA-P384' ? { name: 'ECDSA', namedCurve: 'P-384' }
                            : { name: 'RSA-PSS', hash: 'SHA-256' };
      }
    } catch (e) {
      toast('Key generation failed: ' + e.message);
      btn.disabled = false; btn.innerHTML = 'GENERATE KEYPAIR'; return;
    }

    animateProgress(90, 100, 200);

    state.generatedPrivPem   = privPem;
    state.generatedPubPem    = pubPem;
    state.generatedDHPubPem  = dhPubPem;

    $('priv-key-display').textContent = privPem;
    $('pub-key-display').textContent  = pubPem;

    btn.classList.add('hidden');
    const act = $('btn-activate');
    act.classList.remove('hidden'); act.disabled = true;
    $('confirm-saved').addEventListener('change', function h() {
      act.disabled = !this.checked;
      if (this.checked) this.removeEventListener('change', h);
    });
  }

  function animateProgress(from, to, ms) {
    const fill = $('gen-progress'), start = Date.now();
    const tick = () => {
      const t = Math.min(1, (Date.now() - start) / ms);
      fill.style.width = (from + (to - from) * t) + '%';
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  async function activateAccount() {
    const username = $('reg-username').value.trim();
    const isPQ     = state.generatedAlgo && state.generatedAlgo.name === 'ML-DSA-65';
    const fp       = await Crypto.fingerprint(state.generatedPubPem);

    if (isPQ) {
      await Crypto.persistPQKEMKey(state.generatedDHKeys.secretKey, fp);
    } else {
      await Crypto.persistDHPrivKey(state.generatedDHKeys.privateKey, fp);
    }

    const users = getStoredUsers();
    users[fp] = {
      handle: username,
      publicKeyPem: state.generatedPubPem,
      fingerprint: fp, algo: state.generatedAlgo,
      dhPubKeyPem: state.generatedDHPubPem,
      registeredAt: Date.now(),
    };
    localStorage.setItem('cipher_users', JSON.stringify(users));
    localStorage.setItem('cipher_my_fingerprint', fp);

    state.me = {
      handle: username, publicKeyPem: state.generatedPubPem,
      signingKey: isPQ ? state.generatedCryptoKeys.secretKey
                       : state.generatedCryptoKeys.privateKey,
      fingerprint: fp, algo: state.generatedAlgo,
      dhPrivKey:   isPQ ? state.generatedDHKeys.secretKey
                        : state.generatedDHKeys.privateKey,
      dhPubKeyPem: state.generatedDHPubPem,
    };

    state.generatedPrivPem    = null;
    state.generatedCryptoKeys = null;
    state.generatedDHKeys     = null;

    enterApp();
    Render.sysMsg(username + ' joined the network.');
    toast('Authenticated as ' + username);
  }

  async function importKey() {
    const privPem        = $('login-privkey').value.trim();
    const handleOverride = $('login-username').value.trim();
    hideLoginError();
    if (!privPem) { showLoginError('Paste your private key.'); return; }

    const btn = $('btn-import');
    btn.textContent = 'VERIFYING...'; btn.disabled = true;

    let pemToImport = privPem;
    if (Crypto.isEncryptedKey(privPem)) {
      const pw = $('import-password') && $('import-password').value.trim();
      if (!pw) {
        showLoginError('This key is password-protected. Enter the password in the field above.');
        const pg = $('import-password-group');
        if (pg) { pg.style.display = ''; pg.classList.remove('hidden'); }
        $('import-password') && $('import-password').focus();
        btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
      }
      btn.textContent = 'DECRYPTING...';
      try {
        pemToImport = await Crypto.decryptPrivateKey(privPem, pw);
      } catch (e) {
        showLoginError(e.message);
        btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
      }
    }

    const isPQImport = Crypto.isPQKey(pemToImport);

    let signingKey, publicKeyB64, algo, fp, dhPrivKey, dhPubKeyPem;

    if (isPQImport) {
      let secretKey;
      try {
        secretKey = Crypto.decodePQSecretKey(pemToImport);
      } catch (e) {
        showLoginError(e.message);
        btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
      }
      algo       = { name: 'ML-DSA-65' };
      signingKey = secretKey;

      const users0  = getStoredUsers();
      const myFp0   = localStorage.getItem('cipher_my_fingerprint');
      const stored0 = myFp0 && users0[myFp0];
      if (stored0 && stored0.algo && stored0.algo.name === 'ML-DSA-65') {
        publicKeyB64 = stored0.publicKeyPem;
        fp           = myFp0;
      } else {
        showLoginError('PQ key detected but no matching public key found in this browser. ' +
          'Make sure you are on the same device where the key was generated, ' +
          'or restore a full backup first.');
        btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
      }

      const storedKEM = await Crypto.loadPQKEMKey(fp);
      if (storedKEM) {
        dhPrivKey   = storedKEM;
        dhPubKeyPem = stored0.dhPubKeyPem || null;
      } else {
        const kemKeys = await Crypto.generateMLKEMKeypair();
        dhPrivKey     = kemKeys.secretKey;
        dhPubKeyPem   = Crypto.bytesToB64(kemKeys.publicKey);
        await Crypto.persistPQKEMKey(kemKeys.secretKey, fp);
      }

    } else {
      let keyData;
      try {
        keyData = await Crypto.importPrivateKey(pemToImport);
      } catch (e) {
        showLoginError(e.message);
        btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
      }

      const pubPem  = await Crypto.exportPubPem(keyData.publicKey);
      publicKeyB64  = pubPem;
      algo          = keyData.algorithm;
      signingKey    = keyData.privateKey;
      fp            = await Crypto.fingerprint(pubPem);

      const storedDH = await Crypto.loadDHPrivKey(fp);
      if (storedDH) {
        dhPrivKey   = storedDH;
        dhPubKeyPem = await Crypto.exportPubPem(await Crypto.deriveDHPubFromPriv(dhPrivKey));
      } else {
        const dhKeys = await Crypto.generateDHKeypair();
        dhPrivKey    = dhKeys.privateKey;
        dhPubKeyPem  = await Crypto.exportPubPem(dhKeys.publicKey);
        await Crypto.persistDHPrivKey(dhPrivKey, fp);
      }
    }

    const users  = getStoredUsers();
    const handle = handleOverride || (users[fp] && users[fp].handle) || 'user_' + fp.slice(0,6);
    const existingUser = users[fp] || {};
    users[fp] = { ...existingUser, handle, publicKeyPem: publicKeyB64, fingerprint: fp, algo, dhPubKeyPem };
    localStorage.setItem('cipher_users', JSON.stringify(users));
    localStorage.setItem('cipher_my_fingerprint', fp);

    state.me = { handle, publicKeyPem: publicKeyB64, signingKey, fingerprint: fp, algo, dhPrivKey, dhPubKeyPem };

    $('login-privkey').value   = '';
    $('login-username').value  = '';
    if ($('import-password')) $('import-password').value = '';
    hideLoginError();

    btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false;
    enterApp();
    Render.sysMsg(handle + ' connected.');
    toast('Signed in as ' + handle);
  }

  function enterApp() {
    $('lock-screen').classList.add('hidden');
    $('app').classList.remove('hidden');
    onAuthenticated();
  }

  function switchLockTab(tab) {
    $('lock-tab-register').classList.toggle('active', tab === 'register');
    $('lock-tab-login').classList.toggle('active',    tab === 'login');
    $('lock-panel-register').classList.toggle('hidden', tab !== 'register');
    $('lock-panel-login').classList.toggle('hidden',    tab === 'register');
  }

  function onAuthenticated() {
    Render.updateMsgInput();
    Render.updateUserBadge();
    Render.updateUserList();
    $('auth-btn').textContent = '[ ' + state.me.handle.toUpperCase() + ' // ONLINE ]';
    $('identity-actions').classList.remove('hidden');
    $('identity-actions').classList.add('visible');
    window.CipherNet.Util.showStorageWarning();
    if (window.CipherNet.ChannelUI && window.CipherNet.ChannelUI.initChannelsAfterAuth) {
      window.CipherNet.ChannelUI.initChannelsAfterAuth();
    } else {
      Messaging.loadChannelHistory(state.channel);
    }
  }

  window.CipherNet.LockScreen = {
    generateKeys, animateProgress, activateAccount,
    importKey, enterApp, switchLockTab, onAuthenticated,
  };
})();
