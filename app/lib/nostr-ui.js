window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const Crypto = window.CipherNet.Crypto;
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;
  const scrollToBottom = window.CipherNet.Util.scrollToBottom;
  const { state, getStoredUsers } = window.CipherNet.State;
  const Render = window.CipherNet.Render;

  const nostrEnabled = { value: false };
  const nostrSubs    = {};

  function updateNostrStatusBar() {
    const bar    = $('nostr-status-bar');
    const dot    = $('nostr-dot');
    const label  = $('nostr-label');
    const count  = $('nostr-relay-count');
    if (!bar) return;

    if (!nostrEnabled.value) {
      bar.classList.add('hidden'); return;
    }
    bar.classList.remove('hidden');

    const status = window.CipherNostr ? window.CipherNostr.getStatus() : {};
    const total  = Object.keys(status).length;
    const online = Object.values(status).filter(s => s === 'connected').length;

    count.textContent = online + '/' + total;
    if (online === 0) { dot.className = 'nostr-dot offline'; label.textContent = 'NOSTR'; }
    else              { dot.className = 'nostr-dot online';  label.textContent = 'NOSTR'; }
  }

  function renderRelayList() {
    const list = $('nostr-relay-list');
    if (!list || !window.CipherNostr) return;
    list.innerHTML = '';
    const relays = window.CipherNostr.getRelayList();
    const status = window.CipherNostr.getStatus();
    relays.forEach(url => {
      const st  = status[url] || 'disconnected';
      const row = document.createElement('div');
      row.className = 'nostr-relay-row';
      const dot = document.createElement('span');
      dot.className = 'nostr-relay-dot ' + st;
      const lbl = document.createElement('span');
      lbl.className = 'nostr-relay-url'; lbl.textContent = url;
      lbl.title = st;
      const rm = document.createElement('button');
      rm.className = 'btn-tiny danger'; rm.textContent = 'REMOVE';
      rm.addEventListener('click', () => {
        window.CipherNostr.removeRelay(url);
        renderRelayList();
      });
      row.appendChild(dot); row.appendChild(lbl); row.appendChild(rm);
      list.appendChild(row);
    });
  }

  function openNostrModal() {
    renderRelayList();
    const pub = $('nostr-transport-pub');
    if (pub && window.CipherNostr) pub.textContent = window.CipherNostr.getTransportPubKey() || 'Not initialized';
    $('nostr-modal').classList.remove('hidden');
  }

  async function enableNostr() {
    if (!window.CipherNostr) { toast('nostr.js not loaded'); return; }
    const btn = $('btn-nostr-toggle');
    btn.textContent = 'CONNECTING...'; btn.disabled = true;

    const ok = await window.CipherNostr.init(
      onNostrMessage,
      (url, status) => {
        updateNostrStatusBar();
        renderRelayList();
      }
    );

    nostrEnabled.value = ok;
    btn.textContent = ok ? 'NOSTR: ON' : 'NOSTR: OFF';
    btn.disabled = false;
    btn.classList.toggle('active', ok);

    if (ok) {
      subscribeNostrChannels();
      subscribeNostrDMs();
      updateNostrStatusBar();
      toast('Nostr connected \u2014 syncing messages');
    } else {
      toast('Nostr init failed \u2014 check console');
    }
  }

  function disableNostr() {
    nostrEnabled.value = false;
    for (const subId of Object.values(nostrSubs))
      window.CipherNostr.unsubscribe(subId);
    Object.keys(nostrSubs).forEach(k => delete nostrSubs[k]);
    const btn = $('btn-nostr-toggle');
    btn.textContent = 'NOSTR: OFF';
    btn.classList.remove('active');
    updateNostrStatusBar();
  }

  async function subscribeNostrChannels() {
    for (const ch of ['general', 'random', 'tech']) {
      if (nostrSubs[ch]) window.CipherNostr.unsubscribe(nostrSubs[ch]);
      nostrSubs[ch] = await window.CipherNostr.subscribeChannel(ch, (event, relayUrl) => {
        onNostrChannelEvent(ch, event);
      });
    }
  }

  function subscribeNostrDMs() {
    if (nostrSubs.dms) window.CipherNostr.unsubscribe(nostrSubs.dms);
    nostrSubs.dms = window.CipherNostr.subscribeDMs(async (event, relayUrl) => {
      try {
        const { payload, senderPubKey, ts } = await window.CipherNostr.unwrapDM(event);
        onNostrDMEvent(payload, senderPubKey, ts);
      } catch (e) {
        console.warn('[Nostr] DM unwrap failed:', e.message);
      }
    });
  }

  async function onNostrChannelEvent(channel, event) {
    const ciphertext = event.content;
    const ts         = event.created_at * 1000;
    const authorHint = event.pubkey.slice(0, 6);

    const seenKey = 'cipher_nostr_seen_' + event.id;
    if (sessionStorage.getItem(seenKey)) return;
    sessionStorage.setItem(seenKey, '1');

    window.CipherNet.Messaging.persist('cipher_msgs_' + channel, { ciphertext, ts, authorHint, nostrId: event.id });

    if (state.view === 'channel' && state.channel === channel && state.channelKeys[channel]) {
      try {
        const env      = JSON.parse(await Crypto.aesDecrypt(ciphertext, state.channelKeys[channel]));
        const verified = await Crypto.verifyData(env.sigPayload, env.sig, env.publicKeyPem, env.algo);
        Render.renderMessage({ text: env.text, author: env.handle, fingerprint: env.author, ts, verified, enc: 'AES-256-GCM\u00b7NOSTR' });
        scrollToBottom();
      } catch { /* wrong key or not for us */ }
    }
  }

  async function onNostrDMEvent(payload, senderNostrPub, ts) {
    const users = getStoredUsers();
    let peerFp  = null;
    for (const [fp, u] of Object.entries(users)) {
      if (u.nostrPub === senderNostrPub) { peerFp = fp; break; }
    }
    if (!peerFp) {
      console.log('[Nostr] DM from unknown Nostr pubkey:', senderNostrPub.slice(0,16));
      return;
    }

    const seenKey = 'cipher_nostr_dm_seen_' + ts + '_' + senderNostrPub.slice(0,8);
    if (sessionStorage.getItem(seenKey)) return;
    sessionStorage.setItem(seenKey, '1');

    window.CipherNet.Messaging.persist(
      window.CipherNet.Messaging.dmStorageKey(state.me.fingerprint, peerFp),
      { ciphertext: payload, ts, authorHint: peerFp.slice(0, 6) });

    if (state.view === 'dm' && state.dmPeer && state.dmPeer.fingerprint === peerFp) {
      const dmKey = state.dmKeys[peerFp];
      if (dmKey) {
        try {
          const env      = JSON.parse(await Crypto.aesDecrypt(payload, dmKey));
          const verified = await Crypto.verifyData(env.sigPayload, env.sig, env.publicKeyPem, env.algo);
          Render.renderMessage({ text: env.text, author: env.handle, fingerprint: env.from, ts, verified, enc: 'NOSTR\u00b7NIP44+AES', dm: true });
          scrollToBottom();
        } catch { /* can't decrypt */ }
      }
    }
  }

  function onNostrMessage(event, payload) {
  }

  window._nostrHookChannel = async function(channel, ciphertext) {
    if (!nostrEnabled.value || !window.CipherNostr || !window.CipherNostr.isReady()) return;
    try {
      await window.CipherNostr.publishChannelMessage(channel, ciphertext);
    } catch (e) {
      console.warn('[Nostr] Channel publish failed:', e.message);
    }
  };

  window._nostrHookDM = async function(peerFp, ciphertext) {
    if (!nostrEnabled.value || !window.CipherNostr || !window.CipherNostr.isReady()) return;
    const users = getStoredUsers();
    const peer  = users[peerFp];
    if (!peer || !peer.nostrPub) {
      console.log('[Nostr] Peer has no Nostr pubkey \u2014 DM not sent via Nostr');
      return;
    }
    try {
      await window.CipherNostr.publishDM(peer.nostrPub, ciphertext);
    } catch (e) {
      console.warn('[Nostr] DM publish failed:', e.message);
    }
  };

  function registerNostrPubkey() {
    if (!window.CipherNostr || !state.me) return;
    const nostrPub = window.CipherNostr.getTransportPubKey();
    if (!nostrPub) return;
    const users = getStoredUsers();
    if (users[state.me.fingerprint]) {
      users[state.me.fingerprint].nostrPub = nostrPub;
      localStorage.setItem('cipher_users', JSON.stringify(users));
    }
  }

  document.addEventListener('DOMContentLoaded', function initNostrUI() {
    const toggleBtn = $('btn-nostr-toggle');
    if (toggleBtn) toggleBtn.addEventListener('click', () => {
      if (nostrEnabled.value) disableNostr();
      else enableNostr().then(() => registerNostrPubkey());
    });

    const relaysBtn = $('btn-nostr-relays');
    if (relaysBtn) relaysBtn.addEventListener('click', openNostrModal);

    const closeBtn = $('nostr-modal-close');
    if (closeBtn) closeBtn.addEventListener('click', () => $('nostr-modal').classList.add('hidden'));

    $('nostr-modal') && $('nostr-modal').addEventListener('click', e => {
      if (e.target === $('nostr-modal')) $('nostr-modal').classList.add('hidden');
    });

    const addBtn = $('nostr-relay-add');
    if (addBtn) addBtn.addEventListener('click', () => {
      const input = $('nostr-relay-input');
      const url   = input && input.value.trim();
      if (!url) return;
      if (!url.startsWith('ws://') && !url.startsWith('wss://'))
        { toast('Relay URL must start with ws:// or wss://'); return; }
      window.CipherNostr && window.CipherNostr.addRelay(url);
      if (input) input.value = '';
      renderRelayList();
      toast('Relay added: ' + url);
    });

    const reconnBtn = $('nostr-reconnect-btn');
    if (reconnBtn) reconnBtn.addEventListener('click', () => {
      if (window.CipherNostr) {
        for (const url of window.CipherNostr.getRelayList()) {
          window.CipherNostr.addRelay(url);
        }
        toast('Reconnecting all relays...');
        setTimeout(renderRelayList, 1000);
      }
    });
  });

  window.CipherNet.NostrUI = {
    nostrEnabled, nostrSubs,
    updateNostrStatusBar, renderRelayList, openNostrModal,
    enableNostr, disableNostr,
    subscribeNostrChannels, subscribeNostrDMs,
    onNostrChannelEvent, onNostrDMEvent, onNostrMessage,
    registerNostrPubkey,
  };
})();
