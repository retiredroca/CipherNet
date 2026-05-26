window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const $ = window.CipherNet.Util.$;
  const escHtml = window.CipherNet.Util.escHtml;
  const { state, getStoredUsers } = window.CipherNet.State;

  function renderMessage(msg) {
    const isMe = state.me && msg.fingerprint === state.me.fingerprint;
    const div  = document.createElement('div'); div.className = 'msg';
    const meta = document.createElement('div'); meta.className = 'msg-meta';
    const author = document.createElement('span');
    author.className   = 'msg-author' + (isMe ? ' me' : '') + (msg.system ? ' system' : '');
    author.title       = msg.fingerprint ? 'fp: ' + msg.fingerprint : '';
    author.textContent = msg.author;
    meta.appendChild(author);
    const timeEl = document.createElement('span');
    timeEl.className = 'msg-time';
    timeEl.textContent = new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    meta.appendChild(timeEl);
    if (!msg.system && msg.verified !== undefined) {
      const sigEl = document.createElement('span'); sigEl.className = 'msg-sig';
      const icon  = document.createElement('span'); icon.className = 'verified-icon';
      icon.textContent = msg.verified ? '\u2713' : '\u2717';
      sigEl.appendChild(icon);
      sigEl.appendChild(document.createTextNode(msg.verified ? 'SIGNED' : 'INVALID'));
      meta.appendChild(sigEl);
    }
    if (msg.enc) {
      const encEl = document.createElement('div');
      encEl.className   = msg.dm ? 'msg-dm-badge' : 'msg-enc';
      encEl.textContent = msg.enc;
      meta.appendChild(encEl);
    }
    const body = document.createElement('div');
    body.className   = 'msg-body' + (msg.system ? ' system' : '');
    body.textContent = msg.text;
    div.appendChild(meta); div.appendChild(body);
    $('messages').appendChild(div);
  }

  function renderLocked(ts, hint, wrongKey) {
    const div  = document.createElement('div'); div.className = 'msg';
    const meta = document.createElement('div'); meta.className = 'msg-meta';
    const a    = document.createElement('span'); a.className = 'msg-author system';
    a.textContent = hint ? '...' + hint : '??????';
    const t   = document.createElement('span'); t.className = 'msg-time';
    t.textContent = new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const e   = document.createElement('div');
    e.className   = 'msg-enc' + (wrongKey ? ' failed' : '');
    e.textContent = wrongKey ? 'WRONG KEY' : 'LOCKED';
    meta.appendChild(a); meta.appendChild(t); meta.appendChild(e);
    const body = document.createElement('div'); body.className = 'msg-body system';
    body.textContent = wrongKey ? '[decryption failed - wrong passphrase or key]' : '[encrypted - key required to read]';
    div.appendChild(meta); div.appendChild(body);
    $('messages').appendChild(div);
  }

  function updateEncStatus(active) {
    const el = $('enc-status');
    el.textContent = active ? 'AES-256 ACTIVE' : 'NO KEY SET';
    el.classList.toggle('active', active);
  }

  function sysMsg(text) {
    renderMessage({ text, author: 'SYSTEM', fingerprint: '', ts: Date.now(), system: true });
    window.CipherNet.Util.scrollToBottom();
  }

  function updateMsgInput() {
    let enabled, placeholder, hint;
    if (state.view === 'dm') {
      const hasDmKey = state.dmPeer && !!state.dmKeys[state.dmPeer.fingerprint];
      enabled     = hasDmKey;
      placeholder = hasDmKey ? 'DM @' + state.dmPeer.handle + ' (ECDH encrypted)...' : 'Establishing DM key...';
      hint        = hasDmKey
        ? '> ECDH END-TO-END ENCRYPTED DM \u00b7 ECDSA SIGNED \u00b7 to:' + state.dmPeer.handle
        : '> DM KEY NOT ESTABLISHED';
    } else {
      const hasKey = !!state.channelKeys[state.channel];
      enabled     = hasKey;
      placeholder = hasKey ? 'Message #' + state.channel + ' (AES-256-GCM encrypted)...' : 'Set a channel passphrase to send messages...';
      const isPQSess = state.me && state.me.algo && state.me.algo.name === 'ML-DSA-65';
      hint        = state.me
        ? (hasKey
            ? '> ' + state.me.handle.toUpperCase() + ' \u00b7 AES-256-GCM \u00b7 ' +
              (isPQSess ? 'ML-DSA-65 \u269b PQ-SIGNED' : 'ECDSA SIGNED') +
              ' \u00b7 fp:' + state.me.fingerprint
            : '> SET A CHANNEL PASSPHRASE TO ENABLE ENCRYPTION')
        : '';
    }
    $('msg-input').disabled     = !enabled;
    $('btn-send').disabled      = !enabled;
    $('msg-input').placeholder  = placeholder;
    $('input-hint').textContent = hint;
  }

  function updateUserBadge() {
    if (!state.me) return;
    const badge = $('user-badge');
    badge.classList.remove('hidden'); badge.classList.add('visible');
    badge.innerHTML = '';
    const dot = document.createElement('span'); dot.className = 'dot active';
    const fp  = document.createElement('span'); fp.className = 'badge-fp'; fp.textContent = state.me.fingerprint;
    badge.appendChild(dot);
    badge.appendChild(document.createTextNode(state.me.handle + ' '));
    badge.appendChild(fp);
  }

  function updateUserList() {
    const users   = getStoredUsers();
    const list    = $('user-list');
    list.innerHTML = '';
    const entries  = Object.values(users);
    if (!entries.length) {
      const e = document.createElement('div'); e.className = 'user-empty'; e.textContent = 'No users';
      list.appendChild(e); return;
    }
    entries.forEach(u => {
      const isMe = state.me && u.fingerprint === state.me.fingerprint;
      const div  = document.createElement('div');
      div.className = 'user-item' + (isMe ? ' me' : '');
      div.title     = 'fp: ' + u.fingerprint + (u.dhPubKeyPem ? ' \u00b7 DM key present' : ' \u00b7 No DM key');
      const dot = document.createElement('span'); dot.className = 'user-dot' + (isMe ? ' online' : '');
      const fp  = document.createElement('span'); fp.className = 'user-fp'; fp.textContent = u.fingerprint.slice(0,6);
      div.appendChild(dot);
      div.appendChild(document.createTextNode(u.handle));
      div.appendChild(fp);
      if (!isMe) div.addEventListener('click', () => {
        const C = window.CipherNet;
        if (C.Messaging) C.Messaging.openDM(u.fingerprint);
      });
      list.appendChild(div);
    });
    document.querySelectorAll('.online-count').forEach(el => el.textContent = entries.length);
  }

  window.CipherNet.Render = {
    renderMessage, renderLocked, updateEncStatus, sysMsg,
    updateMsgInput, updateUserBadge, updateUserList,
  };
})();
