window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const Crypto = window.CipherNet.Crypto;
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;
  const escHtml = window.CipherNet.Util.escHtml;
  const scrollToBottom = window.CipherNet.Util.scrollToBottom;
  const { state, getStoredUsers } = window.CipherNet.State;
  const Render = window.CipherNet.Render;

  let _activeSettingsChannelId = null;

  function renderChannelList() {
    const list = $('channel-list');
    if (!list) return;
    list.innerHTML = '';

    const channels = window.CipherChannels ? window.CipherChannels.getJoined() : [];
    if (!channels.length) {
      const e = document.createElement('div');
      e.className   = 'ch-empty';
      e.textContent = 'No channels \u2014 click + to create or join';
      list.appendChild(e);
      return;
    }

    channels.forEach(ch => {
      const div  = document.createElement('div');
      const isActive = state.channel === ch.id;
      div.className  = 'channel-item' + (isActive ? ' active' : '');
      div.dataset.channel = ch.id;

      const role    = state.me ? window.CipherChannels.getRole(ch.id, state.me.fingerprint) : 'guest';
      const hasKey  = window.CipherChannels.canRead(ch.id);
      const lockIcon = ch.passphrase ? (hasKey ? '\ud83d\udd13' : '\ud83d\udd12') : '#';
      const roleTag  = role === 'owner' ? ' \u2605' : role === 'admin' ? ' \u2b06' : '';

      div.innerHTML =
        '<span class="ch-icon">' + lockIcon + '</span>' +
        '<span class="ch-name">' + escHtml(ch.name) + roleTag + '</span>' +
        (ch.type === 'private' ? '<span class="ch-private-badge">PVT</span>' : '');

      div.addEventListener('click', () => switchChannel(ch.id));
      div.addEventListener('contextmenu', e => {
        e.preventDefault();
        openChannelSettings(ch.id);
      });

      list.appendChild(div);
    });
  }

  function switchChannel(channelId) {
    state.view    = 'channel';
    state.channel = channelId;
    state.dmPeer  = null;
    document.querySelectorAll('.channel-item, .dm-item').forEach(el => el.classList.remove('active'));
    const el = document.querySelector('.channel-item[data-channel="' + channelId + '"]');
    if (el) el.classList.add('active');

    const ch = window.CipherChannels ? window.CipherChannels.get(channelId) : null;
    const name = ch ? ch.name : channelId;
    const desc = ch
      ? (ch.passphrase ? 'AES-256-GCM \u00b7 passphrase required \u00b7 ' : 'Open channel \u00b7 ') +
        (ch.type === 'public' ? 'public' : 'private') +
        (ch.nostrId ? ' \u00b7 Nostr synced' : '')
      : '';

    $('channel-title').textContent = '# ' + name;
    $('channel-desc').textContent  = desc;
    $('passphrase-wrap').classList.remove('hidden');
    $('dm-header-info').classList.add('hidden');

    const hasKey = window.CipherChannels
      ? window.CipherChannels.canRead(channelId)
      : !!state.channelKeys[channelId];

    Render.updateEncStatus(hasKey);
    $('messages').innerHTML = '';
    Render.updateMsgInput();
    window.CipherNet.Messaging.loadChannelHistory(channelId);
  }

  function openChannelModal() {
    switchChTab('my');
    renderMyChannels();
    $('channel-modal').classList.remove('hidden');
  }

  function closeChannelModal() {
    $('channel-modal').classList.add('hidden');
  }

  function switchChTab(tab) {
    ['my','browse','create','join'].forEach(t => {
      $('ch-tab-'    + t).classList.toggle('active', t === tab);
      $('ch-panel-'  + t).classList.toggle('hidden',  t !== tab);
    });
  }

  function renderMyChannels() {
    const list = $('ch-my-list');
    if (!list) return;
    list.innerHTML = '';
    const channels = window.CipherChannels ? window.CipherChannels.getJoined() : [];
    if (!channels.length) {
      list.innerHTML = '<div class="ch-empty">You have not joined any channels yet.</div>';
      return;
    }
    channels.forEach(ch => {
      const role   = state.me ? window.CipherChannels.getRole(ch.id, state.me.fingerprint) : 'guest';
      const hasKey = window.CipherChannels.canRead(ch.id);
      list.appendChild(buildChannelRow(ch, role, hasKey, true));
    });
  }

  function renderBrowseChannels() {
    const list = $('ch-browse-list');
    if (!list) return;
    list.innerHTML = '';
    const all    = window.CipherChannels ? window.CipherChannels.getAll() : [];
    const public_ = all.filter(c => c.type === 'public');
    if (!public_.length) {
      list.innerHTML = '<div class="ch-empty">No public channels discovered yet. Enable Nostr to find channels.</div>';
      return;
    }
    public_.forEach(ch => {
      const joined = window.CipherChannels.getJoined().some(c => c.id === ch.id);
      const role   = state.me ? window.CipherChannels.getRole(ch.id, state.me.fingerprint) : null;
      list.appendChild(buildChannelRow(ch, role, false, joined));
    });
  }

  function buildChannelRow(ch, role, hasKey, joined) {
    const div = document.createElement('div');
    div.className = 'ch-row';

    const info = document.createElement('div');
    info.className = 'ch-row-info';
    info.innerHTML =
      '<span class="ch-row-name">' + (ch.passphrase ? '\ud83d\udd12 ' : '# ') + escHtml(ch.name) + '</span>' +
      '<span class="ch-row-type ' + ch.type + '">' + ch.type.toUpperCase() + '</span>' +
      (role === 'owner' ? '<span class="ch-row-role">OWNER</span>' : '') +
      (role === 'admin' ? '<span class="ch-row-role">ADMIN</span>'  : '') +
      (ch.description ? '<div class="ch-row-desc">' + escHtml(ch.description) + '</div>' : '');

    const btns = document.createElement('div');
    btns.className = 'ch-row-btns';

    if (joined) {
      const switchBtn = document.createElement('button');
      switchBtn.className   = 'btn-tiny';
      switchBtn.textContent = 'OPEN';
      switchBtn.addEventListener('click', () => { switchChannel(ch.id); closeChannelModal(); });
      btns.appendChild(switchBtn);

      const settBtn = document.createElement('button');
      settBtn.className   = 'btn-tiny';
      settBtn.textContent = 'SETTINGS';
      settBtn.addEventListener('click', () => { closeChannelModal(); openChannelSettings(ch.id); });
      btns.appendChild(settBtn);

      const leaveBtn = document.createElement('button');
      leaveBtn.className   = 'btn-tiny danger';
      leaveBtn.textContent = role === 'owner' ? 'ARCHIVE' : 'LEAVE';
      leaveBtn.addEventListener('click', async () => {
        if (!confirm(role === 'owner' ? 'Archive this channel?' : 'Leave this channel?')) return;
        if (role === 'owner') {
          await window.CipherChannels.archive(ch.id, state.me.fingerprint, state.me.signingKey, state.me.algo);
        } else {
          window.CipherChannels.leave(ch.id);
        }
        renderMyChannels();
        renderChannelList();
      });
      btns.appendChild(leaveBtn);
    } else {
      const joinBtn = document.createElement('button');
      joinBtn.className   = 'btn-tiny';
      joinBtn.textContent = ch.passphrase ? 'JOIN (needs passphrase)' : 'JOIN';
      joinBtn.addEventListener('click', () => promptJoinChannel(ch));
      btns.appendChild(joinBtn);
    }

    div.appendChild(info);
    div.appendChild(btns);
    return div;
  }

  async function promptJoinChannel(ch) {
    let passphrase = null;
    if (ch.passphrase) {
      passphrase = prompt('Enter passphrase for #' + ch.name + ':');
      if (passphrase === null) return;
    }
    try {
      await window.CipherChannels.join(ch.id, passphrase);
      renderChannelList();
      renderMyChannels();
      toast('Joined #' + ch.name);
      switchChannel(ch.id);
      closeChannelModal();
    } catch (e) { alert('Could not join: ' + e.message); }
  }

  async function createChannel() {
    if (!state.me) { toast('Sign in first'); return; }
    const name = $('ch-create-name').value.trim();
    const desc = $('ch-create-desc').value.trim();
    const type = $('ch-create-type').value;
    const pass = $('ch-create-pass').value || null;
    const errEl = $('ch-create-error');
    errEl.classList.add('hidden');

    const btn = $('ch-create-btn');
    btn.textContent = 'CREATING...'; btn.disabled = true;

    try {
      const ch = await window.CipherChannels.create(
        { name, description: desc, type, passphrase: pass },
        state.me.fingerprint,
        state.me.publicKeyPem,
        state.me.signingKey,
        state.me.algo
      );
      $('ch-create-name').value = '';
      $('ch-create-desc').value = '';
      $('ch-create-pass').value = '';
      renderChannelList();
      toast('Channel #' + ch.name + ' created');
      switchChannel(ch.id);
      closeChannelModal();
    } catch (e) {
      errEl.textContent = e.message;
      errEl.classList.remove('hidden');
    }
    btn.textContent = 'CREATE CHANNEL'; btn.disabled = false;
  }

  async function joinViaInvite() {
    if (!state.me) { toast('Sign in first'); return; }
    const token = $('ch-join-invite').value.trim();
    const errEl = $('ch-join-error');
    errEl.classList.add('hidden');
    if (!token) { errEl.textContent = 'Paste an invite token.'; errEl.classList.remove('hidden'); return; }

    const btn = $('ch-join-btn');
    btn.textContent = 'JOINING...'; btn.disabled = true;

    try {
      const { token: t } = await parseInviteToken(token);
      const users  = getStoredUsers();
      const inviter = users[t.inviterFp];
      if (!inviter) throw new Error('Inviter not found in your user registry. Import their public identity first.');

      const ch = await window.CipherChannels.joinViaInvite(token, inviter.publicKeyPem, inviter.algo);
      $('ch-join-invite').value = '';
      renderChannelList();
      toast('Joined #' + ch.name);
      switchChannel(ch.id);
      closeChannelModal();
    } catch (e) {
      errEl.textContent = e.message;
      errEl.classList.remove('hidden');
    }
    btn.textContent = 'JOIN CHANNEL'; btn.disabled = false;
  }

  async function parseInviteToken(b64) {
    try { return JSON.parse(atob(b64)); }
    catch (e) { throw new Error('Invalid invite token'); }
  }

  async function openChannelSettings(channelId) {
    if (!window.CipherChannels) return;
    const ch   = window.CipherChannels.get(channelId);
    if (!ch) return;
    _activeSettingsChannelId = channelId;

    const role   = state.me ? window.CipherChannels.getRole(channelId, state.me.fingerprint) : 'guest';
    const isOwner = role === 'owner';
    const isAdmin = role === 'admin' || isOwner;

    $('ch-settings-title').textContent = '// #' + ch.name.toUpperCase() + ' \u2014 SETTINGS';
    $('ch-settings-error').classList.add('hidden');

    const badge = $('ch-settings-role-badge');
    badge.textContent = 'YOUR ROLE: ' + role.toUpperCase();
    badge.className   = 'ch-role-badge role-' + role;

    const passSection = $('ch-settings-pass-section');
    passSection.classList.toggle('hidden', !isAdmin);
    if (isAdmin) {
      $('ch-settings-pass-status').textContent = ch.passphrase
        ? 'Currently: passphrase set (write-protected)'
        : 'Currently: open channel (no passphrase)';
      $('ch-settings-pass-input').value = '';
    }

    const adminSection = $('ch-settings-admin-section');
    adminSection.classList.toggle('hidden', !isOwner);
    if (isOwner) renderMemberList(ch);

    $('ch-settings-invite-section').classList.toggle('hidden', !isAdmin);
    $('ch-settings-invite-out').classList.add('hidden');
    $('ch-settings-invite-copy').classList.add('hidden');

    $('ch-settings-archive-section').classList.toggle('hidden', !isOwner);

    $('channel-settings-modal').classList.remove('hidden');
  }

  function renderMemberList(ch) {
    const list  = $('ch-settings-member-list');
    if (!list) return;
    list.innerHTML = '';
    const users = getStoredUsers();

    Object.values(users).forEach(u => {
      if (u.fingerprint === ch.ownerFp) return;
      const isBanned = ch.banned.includes(u.fingerprint);
      const isAdmin  = ch.admins.includes(u.fingerprint);

      const row = document.createElement('div');
      row.className = 'ch-member-row' + (isBanned ? ' banned' : '');

      const name = document.createElement('span');
      name.className   = 'ch-member-name';
      name.textContent = u.handle + ' ' + (isAdmin ? '[ADMIN]' : '') + (isBanned ? '[BANNED]' : '');
      row.appendChild(name);

      if (!isBanned) {
        if (!isAdmin) {
          const promBtn = document.createElement('button');
          promBtn.className   = 'btn-tiny';
          promBtn.textContent = 'PROMOTE';
          promBtn.addEventListener('click', async () => {
            await window.CipherChannels.promote(ch.id, u.fingerprint, state.me.fingerprint, state.me.signingKey, state.me.algo);
            renderMemberList(window.CipherChannels.get(ch.id));
            toast(u.handle + ' promoted to admin');
          });
          row.appendChild(promBtn);
        } else {
          const demBtn = document.createElement('button');
          demBtn.className   = 'btn-tiny';
          demBtn.textContent = 'DEMOTE';
          demBtn.addEventListener('click', async () => {
            await window.CipherChannels.demote(ch.id, u.fingerprint, state.me.fingerprint, state.me.signingKey, state.me.algo);
            renderMemberList(window.CipherChannels.get(ch.id));
            toast(u.handle + ' demoted');
          });
          row.appendChild(demBtn);
        }
        const banBtn = document.createElement('button');
        banBtn.className   = 'btn-tiny danger';
        banBtn.textContent = 'BAN';
        banBtn.addEventListener('click', async () => {
          if (!confirm('Ban ' + u.handle + ' from this channel?')) return;
          await window.CipherChannels.ban(ch.id, u.fingerprint, state.me.fingerprint, state.me.signingKey, state.me.algo);
          renderMemberList(window.CipherChannels.get(ch.id));
          toast(u.handle + ' banned');
        });
        row.appendChild(banBtn);
      } else {
        const unbanBtn = document.createElement('button');
        unbanBtn.className   = 'btn-tiny';
        unbanBtn.textContent = 'UNBAN';
        unbanBtn.addEventListener('click', async () => {
          await window.CipherChannels.unban(ch.id, u.fingerprint, state.me.fingerprint, state.me.signingKey, state.me.algo);
          renderMemberList(window.CipherChannels.get(ch.id));
          toast(u.handle + ' unbanned');
        });
        row.appendChild(unbanBtn);
      }
      list.appendChild(row);
    });

    if (!list.children.length)
      list.innerHTML = '<div class="ch-empty">No other users in registry yet.</div>';
  }

  document.addEventListener('DOMContentLoaded', function initChannelUI() {
    if (!$('ch-tab-my')) return;

    $('ch-tab-my').addEventListener('click',     () => { switchChTab('my');     renderMyChannels(); });
    $('ch-tab-browse').addEventListener('click', () => { switchChTab('browse'); renderBrowseChannels(); });
    $('ch-tab-create').addEventListener('click', () => switchChTab('create'));
    $('ch-tab-join').addEventListener('click',   () => switchChTab('join'));

    ['my','browse','create','join'].forEach(t => {
      const btn = $('ch-modal-close-' + t);
      if (btn) btn.addEventListener('click', closeChannelModal);
    });

    $('channel-modal').addEventListener('click', e => {
      if (e.target === $('channel-modal')) closeChannelModal();
    });

    $('ch-create-btn').addEventListener('click', createChannel);

    $('ch-join-btn').addEventListener('click', joinViaInvite);

    $('ch-browse-refresh').addEventListener('click', renderBrowseChannels);

    $('ch-settings-close').addEventListener('click', () => $('channel-settings-modal').classList.add('hidden'));
    $('channel-settings-modal').addEventListener('click', e => {
      if (e.target === $('channel-settings-modal')) $('channel-settings-modal').classList.add('hidden');
    });

    $('ch-settings-pass-btn').addEventListener('click', async () => {
      const id   = _activeSettingsChannelId;
      const pass = $('ch-settings-pass-input').value || null;
      const errEl = $('ch-settings-error');
      try {
        await window.CipherChannels.setPassphrase(id, pass, state.me.fingerprint, state.me.signingKey, state.me.algo);
        errEl.classList.add('hidden');
        toast('Passphrase updated for #' + window.CipherChannels.get(id).name);
        openChannelSettings(id);
      } catch (e) { errEl.textContent = e.message; errEl.classList.remove('hidden'); }
    });

    $('ch-settings-invite-btn').addEventListener('click', async () => {
      const id = _activeSettingsChannelId;
      try {
        const token = await window.CipherChannels.invite(id, state.me.fingerprint, state.me.signingKey, state.me.algo);
        const out = $('ch-settings-invite-out');
        const copyBtn = $('ch-settings-invite-copy');
        out.value = token;
        out.classList.remove('hidden');
        copyBtn.classList.remove('hidden');
        copyBtn.onclick = () => {
          navigator.clipboard.writeText(token).then(() => toast('Invite token copied'));
        };
      } catch (e) {
        $('ch-settings-error').textContent = e.message;
        $('ch-settings-error').classList.remove('hidden');
      }
    });

    $('ch-settings-archive-btn').addEventListener('click', async () => {
      const id = _activeSettingsChannelId;
      const ch = window.CipherChannels.get(id);
      if (!confirm('Archive #' + ch.name + '? This cannot be undone.')) return;
      try {
        await window.CipherChannels.archive(id, state.me.fingerprint, state.me.signingKey, state.me.algo);
        $('channel-settings-modal').classList.add('hidden');
        renderChannelList();
        toast('Channel archived');
      } catch (e) {
        $('ch-settings-error').textContent = e.message;
        $('ch-settings-error').classList.remove('hidden');
      }
    });

    if (window.CipherChannels) {
      window.CipherChannels.init(() => {
        renderChannelList();
      });
      window._channelNostrHandler = async (channelId, event) => {
        const ch = window.CipherChannels.get(channelId);
        if (!ch) return;
        const ciphertext = event.content;
        const ts         = event.created_at * 1000;
        const seenKey    = 'cipher_nostr_ch_seen_' + event.id;
        if (sessionStorage.getItem(seenKey)) return;
        sessionStorage.setItem(seenKey, '1');
        const msgKey = window.CipherChannels.msgKey(channelId);
        window.CipherNet.Messaging.persist(msgKey, { ciphertext, ts, authorHint: event.pubkey.slice(0,6), nostrId: event.id });
        if (state.view === 'channel' && state.channel === channelId) {
          const aesKey = window.CipherChannels.getActiveKey(channelId);
          if (aesKey) {
            try {
              const env      = JSON.parse(await Crypto.aesDecrypt(ciphertext, aesKey));
              const verified = await Crypto.verifyData(env.sigPayload, env.sig, env.publicKeyPem, env.algo);
              Render.renderMessage({ text: env.text, author: env.handle, fingerprint: env.author,
                              ts, verified, enc: 'AES-256-GCM\u00b7NOSTR' });
              scrollToBottom();
            } catch {}
          }
        }
      };
    }
  });

  function initChannelsAfterAuth() {
    if (!window.CipherChannels) return;
    window.CipherChannels.restoreKeys().then(() => {
      renderChannelList();
      const joined = window.CipherChannels.getJoined();
      if (joined.length) switchChannel(joined[0].id);
      else {
        $('channel-title').textContent = 'CIPHER//NET';
        $('channel-desc').textContent  = 'Create or join a channel to start chatting';
      }
    });
  }

  window.CipherNet.ChannelUI = {
    renderChannelList, switchChannel,
    openChannelModal, closeChannelModal, switchChTab,
    renderMyChannels, renderBrowseChannels, buildChannelRow,
    promptJoinChannel, createChannel, joinViaInvite, parseInviteToken,
    openChannelSettings, renderMemberList,
    initChannelsAfterAuth, _activeSettingsChannelId,
  };
})();
