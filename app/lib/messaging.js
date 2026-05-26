window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const Crypto = window.CipherNet.Crypto;
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;
  const scrollToBottom = window.CipherNet.Util.scrollToBottom;
  const showDMModalError = window.CipherNet.Util.showDMModalError;
  const closeDMModal = window.CipherNet.Util.closeDMModal;
  const { state, getStoredUsers } = window.CipherNet.State;
  const Render = window.CipherNet.Render;

  async function sendMessage() {
    if (!state.me) return;
    const text = $('msg-input').value.trim();
    if (!text) return;
    $('msg-input').value = '';
    if (state.view === 'dm') await sendDM(text);
    else                     await sendChannelMessage(text);
  }

  async function sendChannelMessage(text) {
    const aesKey = (window.CipherChannels && window.CipherChannels.getActiveKey(state.channel))
                 || state.channelKeys[state.channel];
    if (!aesKey && (window.CipherChannels ? window.CipherChannels.get(state.channel)?.passphrase : true)) {
      toast('Set a channel passphrase first'); return;
    }
    const ts         = Date.now();
    const sigPayload = JSON.stringify({ text, channel: state.channel, author: state.me.fingerprint, ts });
    const sig        = await Crypto.signData(sigPayload, state.me.signingKey, state.me.algo);
    const envelope   = JSON.stringify({
      text, sig, sigPayload, algo: state.me.algo,
      author: state.me.fingerprint, handle: state.me.handle,
      publicKeyPem: state.me.publicKeyPem, ts,
    });
    const ciphertext = await Crypto.aesEncrypt(envelope, aesKey);
    const _msgKey = window.CipherChannels
      ? window.CipherChannels.msgKey(state.channel)
      : 'cipher_msgs_' + state.channel;
    persist(_msgKey, { ciphertext, ts, authorHint: state.me.fingerprint.slice(0,6) });
    if (window._nostrHookChannel) window._nostrHookChannel(state.channel, ciphertext);
    Render.renderMessage({ text, author: state.me.handle, fingerprint: state.me.fingerprint, ts, verified: true, enc: 'AES-256-GCM' });
    scrollToBottom();
  }

  async function sendDM(text) {
    const fp    = state.dmPeer.fingerprint;
    const dmKey = state.dmKeys[fp];
    if (!dmKey) { toast('DM key not established'); return; }
    const ts         = Date.now();
    const sigPayload = JSON.stringify({ text, dm: true, to: fp, from: state.me.fingerprint, ts });
    const sig        = await Crypto.signData(sigPayload, state.me.signingKey, state.me.algo);
    const envelope   = JSON.stringify({
      text, sig, sigPayload, algo: state.me.algo,
      from: state.me.fingerprint, handle: state.me.handle,
      publicKeyPem: state.me.publicKeyPem, ts,
    });
    const ciphertext  = await Crypto.aesEncrypt(envelope, dmKey);
    const isPQDM      = state.me.algo && state.me.algo.name === 'ML-DSA-65';
    const kemCt       = isPQDM && state.dmKemCiphertexts && state.dmKemCiphertexts[fp];
    const entry       = { ciphertext, ts, authorHint: state.me.fingerprint.slice(0,6) };
    if (kemCt) entry.kemCiphertext = kemCt;
    persist(dmStorageKey(state.me.fingerprint, fp), entry);
    if (window._nostrHookDM) window._nostrHookDM(fp, ciphertext);
    Render.renderMessage({ text, author: state.me.handle, fingerprint: state.me.fingerprint, ts, verified: true,
                    enc: isPQDM ? 'ML-KEM-768+AES' : 'ECDH+AES', dm: true });
    scrollToBottom();
  }

  function dmStorageKey(a, b) { return 'cipher_dm_' + [a,b].sort().join('_'); }

  function persist(key, entry) {
    try {
      const arr = JSON.parse(localStorage.getItem(key) || '[]');
      arr.push(entry);
      if (arr.length > 200) arr.splice(0, arr.length - 200);
      localStorage.setItem(key, JSON.stringify(arr));
    } catch { /* storage full */ }
  }

  async function loadHistory() {
    if (state.view === 'dm') await loadDMHistory(state.dmPeer.fingerprint);
    else                     await loadChannelHistory(state.channel);
  }

  async function loadChannelHistory(channel) {
    const aesKey = (window.CipherChannels && window.CipherChannels.getActiveKey(channel))
                 || state.channelKeys[channel];
    const msgKey  = window.CipherChannels
      ? window.CipherChannels.msgKey(channel)
      : 'cipher_msgs_' + channel;
    const stored = JSON.parse(localStorage.getItem(msgKey) || '[]');
    for (const entry of stored) {
      if (!aesKey) { Render.renderLocked(entry.ts, entry.authorHint, false); continue; }
      try {
        const env      = JSON.parse(await Crypto.aesDecrypt(entry.ciphertext, aesKey));
        const verified = await Crypto.verifyData(env.sigPayload, env.sig, env.publicKeyPem, env.algo);
        Render.renderMessage({ text: env.text, author: env.handle, fingerprint: env.author, ts: env.ts, verified, enc: 'AES-256-GCM' });
      } catch { Render.renderLocked(entry.ts, entry.authorHint, true); }
    }
    scrollToBottom();
  }

  async function loadDMHistory(peerFp) {
    const dmKey  = state.dmKeys[peerFp];
    const stored = JSON.parse(localStorage.getItem(dmStorageKey(state.me.fingerprint, peerFp)) || '[]');
    for (const entry of stored) {
      if (!dmKey) { Render.renderLocked(entry.ts, entry.authorHint, false); continue; }
      try {
        let activeDmKey = dmKey;
        if (!activeDmKey && entry.kemCiphertext && state.me.algo && state.me.algo.name === 'ML-DSA-65' && state.me.dhPrivKey) {
          try {
            const sharedSecret = await Crypto.kemDecapsulate(entry.kemCiphertext, Crypto.bytesToB64(state.me.dhPrivKey));
            activeDmKey = await Crypto.kemSharedSecretToAES(sharedSecret);
            state.dmKeys[peerFp] = activeDmKey;
          } catch { /* decapsulation failed */ }
        }
        if (!activeDmKey) { Render.renderLocked(entry.ts, entry.authorHint, false); continue; }
        const env      = JSON.parse(await Crypto.aesDecrypt(entry.ciphertext, activeDmKey));
        const isPQEnv  = env.algo && env.algo.name === 'ML-DSA-65';
        const verified = await Crypto.verifyData(env.sigPayload, env.sig, env.publicKeyPem, env.algo);
        Render.renderMessage({ text: env.text, author: env.handle, fingerprint: env.from, ts: env.ts, verified,
                        enc: isPQEnv ? 'ML-KEM-768+AES' : 'ECDH+AES', dm: true });
      } catch { Render.renderLocked(entry.ts, entry.authorHint, true); }
    }
    scrollToBottom();
  }

  async function openDM(fp) {
    if (fp === state.me.fingerprint) { toast('Cannot DM yourself'); return; }
    const users = getStoredUsers();
    const peer  = users[fp];
    if (!peer) { toast('User not found'); return; }
    if (state.dmKeys[fp]) { activateDMView(peer); return; }
    if (peer.dhPubKeyPem) {
      try {
        if (state.me.algo && state.me.algo.name === 'ML-DSA-65') {
          const { ciphertext, sharedSecret } = await Crypto.kemEncapsulate(peer.dhPubKeyPem);
          state.dmKeys[fp]              = await Crypto.kemSharedSecretToAES(sharedSecret);
          if (!state.dmKemCiphertexts)    state.dmKemCiphertexts = {};
          state.dmKemCiphertexts[fp]    = Crypto.bytesToB64(ciphertext);
        } else {
          state.dmKeys[fp] = await Crypto.deriveSharedDMKey(state.me.dhPrivKey, peer.dhPubKeyPem);
        }
        activateDMView(peer); return;
      } catch (e) { toast('DM key derivation failed: ' + e.message); return; }
    }
    state.pendingDmFp = fp;
    $('dm-modal-error').classList.add('hidden');
    $('dm-pubkey-input').value = '';
    $('dm-key-modal').classList.remove('hidden');
  }

  async function confirmDMKeyExchange() {
    const pem = $('dm-pubkey-input').value.trim();
    const fp  = state.pendingDmFp;
    if (!pem) { showDMModalError('Paste the recipient DM public key.'); return; }
    const btn = $('dm-modal-confirm');
    btn.textContent = 'DERIVING KEY...'; btn.disabled = true;
    try {
      state.dmKeys[fp] = await Crypto.deriveSharedDMKey(state.me.dhPrivKey, pem);
      const users = getStoredUsers();
      if (users[fp]) { users[fp].dhPubKeyPem = pem; localStorage.setItem('cipher_users', JSON.stringify(users)); }
      closeDMModal();
      const peer = getStoredUsers()[fp];
      if (peer) activateDMView(peer);
      toast('DM key established \u2014 ECDH P-256');
    } catch (e) { showDMModalError('Key derivation failed: ' + e.message); }
    btn.textContent = 'START ENCRYPTED DM'; btn.disabled = false;
  }

  function activateDMView(peer) {
    state.view    = 'dm';
    state.dmPeer  = peer;
    state.channel = 'dm:' + peer.fingerprint;
    document.querySelectorAll('.channel-item, .dm-item').forEach(el => el.classList.remove('active'));
    let dmItem = document.querySelector('.dm-item[data-fp="' + peer.fingerprint + '"]');
    if (!dmItem) dmItem = addDMSidebarItem(peer);
    dmItem.classList.add('active');
    $('channel-title').textContent = '@' + peer.handle;
    $('channel-desc').textContent  = 'ECDH P-256 end-to-end encrypted direct message';
    $('passphrase-wrap').classList.add('hidden');
    $('dm-header-info').classList.remove('hidden');
    $('dm-fp').textContent = 'fp:' + peer.fingerprint.slice(0,12);
    $('messages').innerHTML = '';
    Render.updateMsgInput();
    loadHistory();
  }

  function addDMSidebarItem(peer) {
    const list  = $('dm-list');
    const empty = list.querySelector('.dm-empty');
    if (empty) empty.remove();
    const div = document.createElement('div');
    div.className  = 'dm-item';
    div.dataset.fp = peer.fingerprint;
    div.innerHTML  = '<span class="dm-icon">@</span>' + peer.handle +
                     '<span class="user-fp">' + peer.fingerprint.slice(0,6) + '</span>';
    div.addEventListener('click', () => openDM(peer.fingerprint));
    list.appendChild(div);
    return div;
  }

  async function setChannelPassphrase() {
    const pass = $('channel-passphrase').value;
    if (!pass) { toast('Enter a passphrase first'); return; }
    const btn = $('btn-set-passphrase');
    btn.textContent = '...'; btn.disabled = true;
    try {
      state.channelKeys[state.channel] = await Crypto.deriveChannelKey(pass, state.channel);
      $('channel-passphrase').value = '';
      Render.updateEncStatus(true);
      Render.updateMsgInput();
      $('messages').innerHTML = '';
      await loadHistory();
      Render.sysMsg('Channel key active. AES-256-GCM encryption enabled.');
      toast('Channel key set');
    } catch (e) { toast('Key derivation failed: ' + e.message); }
    btn.textContent = 'SET KEY'; btn.disabled = false;
  }

  async function copyKey(which) {
    let text = which === 'priv' ? state.generatedPrivPem : state.generatedPubPem;
    if (!text) return;

    if (which === 'priv') {
      const pw = $('export-password') && $('export-password').value;
      if (pw && pw.trim()) {
        const btn = $('copy-priv-btn');
        const orig = btn.textContent;
        btn.textContent = 'ENCRYPTING...'; btn.disabled = true;
        try {
          text = await Crypto.encryptPrivateKey(text, pw.trim());
          $('export-hint').textContent = '\u2713 Encrypted key copied \u2014 you will need this password to import.';
          $('export-hint').style.color = 'var(--green3)';
        } catch (e) {
          toast('Encryption failed: ' + e.message);
          btn.textContent = orig; btn.disabled = false; return;
        }
        btn.textContent = orig; btn.disabled = false;
      } else {
        const hint = $('export-hint');
        if (hint) {
          hint.textContent = 'Plain key copied \u2014 no password set.';
          hint.style.color = 'var(--amber)';
        }
      }
    }

    navigator.clipboard.writeText(text)
      .then(() => toast(which === 'priv' ? 'Private key copied' : 'Public key copied'))
      .catch(() => {
        const ta = Object.assign(document.createElement('textarea'), { value: text });
        document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
        toast('Copied');
      });
  }

  window.CipherNet.Messaging = {
    sendMessage, sendChannelMessage, sendDM,
    dmStorageKey, persist,
    loadHistory, loadChannelHistory, loadDMHistory,
    openDM, confirmDMKeyExchange, activateDMView, addDMSidebarItem,
    setChannelPassphrase, copyKey,
  };
})();
