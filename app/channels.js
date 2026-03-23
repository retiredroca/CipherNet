'use strict';

// ═══════════════════════════════════════════════════════
// CIPHER//NET — channels.js
// Custom channels with roles, permissions, passphrase control
//
// Channel types:
//   public  — discoverable via Nostr kind 40, anyone can join
//   private — invite-only, joined via signed token
//
// Roles (crypto-enforced via passphrase + signed events):
//   owner   — created channel, holds admin signing key
//   admin   — promoted by owner, can ban / set passphrase
//   member  — has write passphrase
//   guest   — can read open channels, cannot write to locked ones
//   banned  — fingerprint on ban list, messages ignored locally
//
// Nostr kinds used:
//   40   — channel creation metadata (event ID = canonical channel ID)
//   42   — channel message
//   9734 — admin event (ban, promote, passphrase change, archive)
// ═══════════════════════════════════════════════════════

// ── Storage keys ─────────────────────────────────────────
const CHANNELS_KEY = 'cipher_channels_v2';
const JOINED_KEY   = 'cipher_joined_channels';

// ── In-memory state ──────────────────────────────────────
const channelState = {
  channels:   {},    // id → Channel object
  joined:     [],    // ordered list of joined channel IDs
  activeKeys: {},    // id → CryptoKey (AES-GCM)
  onUpdate:   null,  // callback fired when channel list changes
};

// ── Re-entrancy guard ────────────────────────────────────
// Prevents onUpdate from firing recursively if something inside
// the callback causes another state change.
let _onUpdateRunning = false;
function fireOnUpdate() {
  if (_onUpdateRunning || !channelState.onUpdate) return;
  _onUpdateRunning = true;
  try { channelState.onUpdate(); }
  finally { _onUpdateRunning = false; }
}

// ── Persistence ──────────────────────────────────────────

function saveChannels() {
  localStorage.setItem(CHANNELS_KEY, JSON.stringify(channelState.channels));
  localStorage.setItem(JOINED_KEY,   JSON.stringify(channelState.joined));
}

function loadChannels() {
  try {
    channelState.channels = JSON.parse(localStorage.getItem(CHANNELS_KEY) || '{}');
    channelState.joined   = JSON.parse(localStorage.getItem(JOINED_KEY)   || '[]');
  } catch {
    channelState.channels = {};
    channelState.joined   = [];
  }
}

// ── Passphrase key storage ───────────────────────────────

function saveChannelKey(channelId, passphrase) {
  localStorage.setItem('cipher_chan_pass_' + channelId, passphrase);
}

function loadChannelPassphrase(channelId) {
  return localStorage.getItem('cipher_chan_pass_' + channelId);
}

function clearChannelKey(channelId) {
  localStorage.removeItem('cipher_chan_pass_' + channelId);
  delete channelState.activeKeys[channelId];
}

// ── AES key derivation ───────────────────────────────────

async function deriveChannelAESKey(passphrase, channelId) {
  const enc  = new TextEncoder();
  const base = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  const salt = await crypto.subtle.digest(
    'SHA-256', enc.encode('ciphernet-channel-v2:' + channelId)
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ── Channel ID derivation ────────────────────────────────
// Used to generate a local ID before Nostr publishes the channel.
// Once published, the Nostr event ID replaces this as canonical.

async function deriveChannelId(name, ownerFp) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode('ciphernet-channel-v2:' + name + ':' + ownerFp)
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Admin event signing ──────────────────────────────────

async function signAdminEvent(payload, signingKey, algo) {
  const sig = await signData(JSON.stringify(payload), signingKey, algo);
  return { payload, sig, ts: Date.now() };
}

function publishAdminEvent(channelId, event) {
  // Persist locally
  const key  = 'cipher_chan_admin_' + channelId;
  const list = JSON.parse(localStorage.getItem(key) || '[]');
  list.push(event);
  localStorage.setItem(key, JSON.stringify(list));
  // Broadcast via Nostr if connected
  if (window.CipherNostr && window.CipherNostr.isReady()) {
    window.CipherNostr.publishRaw(
      9734, JSON.stringify(event), [['e', channelId]]
    ).catch(() => {});
  }
}

// ── Nostr publish ────────────────────────────────────────
// Publishes a kind 40 event. The returned event ID becomes the
// canonical channel ID so all instances subscribe to the same root.

async function publishToNostr(ch) {
  if (!window.CipherNostr || !window.CipherNostr.isReady()) return null;
  const content = JSON.stringify({
    name:    ch.name,
    about:   ch.description,
    picture: '',
    ciphernet: {
      type:       ch.type,
      ownerFp:    ch.ownerFp,
      ownerPub:   ch.ownerPub,
      passphrase: ch.passphrase,
      admins:     ch.admins,
      banned:     ch.banned,
      archived:   ch.archived || false,
      version:    2,
    },
  });
  const nostrId = await window.CipherNostr.publishRaw(40, content, []);
  if (nostrId && nostrId !== ch.nostrId) {
    ch.nostrId = nostrId;
    channelState.channels[ch.id] = ch;
    saveChannels();
    // Notify app.js to subscribe to kind 42 messages for this channel
    if (window.subscribeNostrOneChannel) window.subscribeNostrOneChannel(ch);
  }
  return nostrId;
}

// ── Invite tokens ────────────────────────────────────────

async function generateInvite(channelId, inviterFp, inviterSigningKey, inviterAlgo, passphrase) {
  const ch = channelState.channels[channelId];
  const token = {
    channelId,
    inviterFp,
    passphrase: passphrase || null,
    expires: Date.now() + 7 * 24 * 60 * 60 * 1000,
    nonce: Array.from(crypto.getRandomValues(new Uint8Array(8)))
      .map(b => b.toString(16).padStart(2, '0')).join(''),
    // Channel metadata embedded so recipient can join without prior knowledge
    channelMeta: ch ? {
      name:        ch.name,
      description: ch.description,
      type:        ch.type,
      ownerFp:     ch.ownerFp,
      ownerPub:    ch.ownerPub,
      created:     ch.created,
    } : null,
  };
  const sig = await signData(JSON.stringify(token), inviterSigningKey, inviterAlgo);
  return btoa(JSON.stringify({ token, sig }));
}

async function parseInvite(b64) {
  try {
    const invite = JSON.parse(atob(b64));
    const { token, sig } = invite;
    if (Date.now() > token.expires) throw new Error('Invite expired');
    return { token, sig };
  } catch (e) {
    throw new Error('Invalid invite: ' + e.message);
  }
}

// ── Public API ───────────────────────────────────────────

const Channels = {

  init(onUpdate) {
    channelState.onUpdate = onUpdate;
    loadChannels();
  },

  getAll() {
    return Object.values(channelState.channels)
      .filter(c => !c.archived)
      .sort((a, b) => {
        const ai = channelState.joined.indexOf(a.id);
        const bi = channelState.joined.indexOf(b.id);
        if (ai !== -1 && bi !== -1) return ai - bi;
        if (ai !== -1) return -1;
        if (bi !== -1) return 1;
        return b.created - a.created;
      });
  },

  getJoined() {
    return channelState.joined
      .map(id => channelState.channels[id])
      .filter(Boolean)
      .filter(c => !c.archived);
  },

  get(id) {
    return channelState.channels[id] || null;
  },

  getRole(channelId, fingerprint) {
    const ch = channelState.channels[channelId];
    if (!ch) return null;
    if (ch.banned.includes(fingerprint)) return 'banned';
    if (ch.ownerFp === fingerprint)       return 'owner';
    if (ch.admins.includes(fingerprint))  return 'admin';
    if (channelState.joined.includes(channelId))
      return loadChannelPassphrase(channelId) ? 'member' : 'guest';
    return 'guest';
  },

  canWrite(channelId, fingerprint) {
    const ch = channelState.channels[channelId];
    if (!ch) return false;
    if (this.getRole(channelId, fingerprint) === 'banned') return false;
    if (!ch.passphrase) return true;
    return !!channelState.activeKeys[channelId];
  },

  canRead(channelId) {
    const ch = channelState.channels[channelId];
    if (!ch) return false;
    if (!ch.passphrase) return true;
    return !!channelState.activeKeys[channelId];
  },

  getActiveKey(channelId) {
    return channelState.activeKeys[channelId] || null;
  },

  msgKey(channelId) {
    return 'cipher_msgs_ch_' + channelId;
  },

  // ── Create channel ──────────────────────────────────────

  async create(opts, ownerFp, ownerPubKeyPem, ownerSigningKey, ownerAlgo) {
    const { name, description = '', type = 'public', passphrase = null } = opts;
    if (!name || !/^[a-zA-Z0-9_\-\s]{1,64}$/.test(name))
      throw new Error('Channel name: 1-64 chars, letters/numbers/spaces/_/-');

    const id = await deriveChannelId(name.trim(), ownerFp);
    if (channelState.channels[id])
      throw new Error('You already have a channel with this name');

    const ch = {
      id,
      name:        name.trim(),
      description,
      type,
      ownerFp,
      ownerPub:    ownerPubKeyPem,
      created:     Date.now(),
      archived:    false,
      passphrase:  !!passphrase,
      admins:      [],
      banned:      [],
      nostrId:     null,
    };

    channelState.channels[id] = ch;
    if (!channelState.joined.includes(id)) channelState.joined.unshift(id);

    if (passphrase) {
      saveChannelKey(id, passphrase);
      channelState.activeKeys[id] = await deriveChannelAESKey(passphrase, id);
    }

    saveChannels();

    // Publish to Nostr if connected — event ID becomes the canonical channel ID
    if (window.CipherNostr && window.CipherNostr.isReady() && type === 'public') {
      try {
        await publishToNostr(ch);
      } catch (e) {
        console.warn('[Channels] Nostr publish failed:', e.message);
      }
    }

    // Subscribe to Nostr messages for this channel
    if (window.subscribeNostrOneChannel) window.subscribeNostrOneChannel(ch);

    fireOnUpdate();
    return ch;
  },

  // ── Join channel ────────────────────────────────────────

  async join(channelId, passphrase) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (!channelState.joined.includes(channelId))
      channelState.joined.unshift(channelId);

    if (passphrase) {
      saveChannelKey(channelId, passphrase);
      channelState.activeKeys[channelId] = await deriveChannelAESKey(passphrase, channelId);
    }

    saveChannels();

    // Subscribe to Nostr messages for this channel
    if (window.subscribeNostrOneChannel) window.subscribeNostrOneChannel(ch);

    fireOnUpdate();
    return ch;
  },

  // ── Join via invite ─────────────────────────────────────

  async joinViaInvite(b64Invite, inviterPubKeyPem, inviterAlgo) {
    const { token, sig } = await parseInvite(b64Invite);

    const valid = await verifyData(JSON.stringify(token), sig, inviterPubKeyPem, inviterAlgo);
    if (!valid) throw new Error('Invite signature invalid — token may be corrupted or forged');

    // Reconstruct channel from embedded metadata if not already known locally
    if (!channelState.channels[token.channelId]) {
      if (!token.channelMeta)
        throw new Error(
          'Channel not found locally and invite has no metadata. ' +
          'Ask the owner to generate a new invite token.'
        );
      const m = token.channelMeta;
      channelState.channels[token.channelId] = {
        id:          token.channelId,
        name:        m.name,
        description: m.description || '',
        type:        m.type || 'private',
        ownerFp:     m.ownerFp,
        ownerPub:    m.ownerPub || '',
        created:     m.created || Date.now(),
        archived:    false,
        passphrase:  !!token.passphrase,
        admins:      [],
        banned:      [],
        nostrId:     null,
      };
      saveChannels();
    }

    return this.join(token.channelId, token.passphrase);
  },

  // ── Leave channel ───────────────────────────────────────

  leave(channelId) {
    channelState.joined = channelState.joined.filter(id => id !== channelId);
    clearChannelKey(channelId);
    saveChannels();
    fireOnUpdate();
  },

  // ── Set passphrase (owner / admin only) ─────────────────

  async setPassphrase(channelId, newPassphrase, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    const role = this.getRole(channelId, actorFp);
    if (role !== 'owner' && role !== 'admin')
      throw new Error('Only owner or admin can change the passphrase');

    ch.passphrase = !!newPassphrase;
    if (newPassphrase) {
      saveChannelKey(channelId, newPassphrase);
      channelState.activeKeys[channelId] = await deriveChannelAESKey(newPassphrase, channelId);
    } else {
      clearChannelKey(channelId);
    }

    publishAdminEvent(channelId, await signAdminEvent(
      { action: 'set_passphrase', channelId, hasPassphrase: ch.passphrase, ts: Date.now() },
      actorSigningKey, actorAlgo
    ));

    if (window.CipherNostr && window.CipherNostr.isReady())
      publishToNostr(ch).catch(() => {});

    saveChannels();
    fireOnUpdate();
  },

  // ── Ban (owner only) ────────────────────────────────────

  async ban(channelId, targetFp, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (this.getRole(channelId, actorFp) !== 'owner')
      throw new Error('Only the owner can ban users');
    if (targetFp === actorFp) throw new Error('Cannot ban yourself');

    if (!ch.banned.includes(targetFp)) ch.banned.push(targetFp);
    ch.admins = ch.admins.filter(f => f !== targetFp);

    publishAdminEvent(channelId, await signAdminEvent(
      { action: 'ban', channelId, targetFp, ts: Date.now() },
      actorSigningKey, actorAlgo
    ));

    saveChannels();
    fireOnUpdate();
  },

  // ── Unban (owner only) ──────────────────────────────────

  async unban(channelId, targetFp, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (this.getRole(channelId, actorFp) !== 'owner')
      throw new Error('Only the owner can unban users');

    ch.banned = ch.banned.filter(f => f !== targetFp);

    publishAdminEvent(channelId, await signAdminEvent(
      { action: 'unban', channelId, targetFp, ts: Date.now() },
      actorSigningKey, actorAlgo
    ));

    saveChannels();
    fireOnUpdate();
  },

  // ── Promote to admin (owner only) ───────────────────────

  async promote(channelId, targetFp, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (this.getRole(channelId, actorFp) !== 'owner')
      throw new Error('Only the owner can promote admins');

    if (!ch.admins.includes(targetFp)) ch.admins.push(targetFp);
    ch.banned = ch.banned.filter(f => f !== targetFp);

    publishAdminEvent(channelId, await signAdminEvent(
      { action: 'promote', channelId, targetFp, ts: Date.now() },
      actorSigningKey, actorAlgo
    ));

    saveChannels();
    fireOnUpdate();
  },

  // ── Demote admin (owner only) ────────────────────────────

  async demote(channelId, targetFp, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (this.getRole(channelId, actorFp) !== 'owner')
      throw new Error('Only the owner can demote admins');

    ch.admins = ch.admins.filter(f => f !== targetFp);

    publishAdminEvent(channelId, await signAdminEvent(
      { action: 'demote', channelId, targetFp, ts: Date.now() },
      actorSigningKey, actorAlgo
    ));

    saveChannels();
    fireOnUpdate();
  },

  // ── Archive channel (owner only) ────────────────────────

  async archive(channelId, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (ch.ownerFp !== actorFp) throw new Error('Only the owner can archive a channel');

    ch.archived = true;
    channelState.joined = channelState.joined.filter(id => id !== channelId);

    publishAdminEvent(channelId, await signAdminEvent(
      { action: 'archive', channelId, ts: Date.now() },
      actorSigningKey, actorAlgo
    ));

    if (window.CipherNostr && window.CipherNostr.isReady())
      publishToNostr(ch).catch(() => {});

    saveChannels();
    fireOnUpdate();
  },

  // ── Generate invite token ────────────────────────────────

  async invite(channelId, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    const role = this.getRole(channelId, actorFp);
    if (role !== 'owner' && role !== 'admin')
      throw new Error('Only owner or admin can generate invites');

    return generateInvite(
      channelId, actorFp, actorSigningKey, actorAlgo,
      loadChannelPassphrase(channelId)
    );
  },

  // ── Import channel discovered via Nostr kind 40 ──────────

  async importFromNostr(kind40Event) {
    try {
      const meta = JSON.parse(kind40Event.content);
      if (!meta.name || !meta.ciphernet) return;

      const id = kind40Event.id;

      // If already known, only update archived state
      if (channelState.channels[id]) {
        if (meta.ciphernet.archived && !channelState.channels[id].archived) {
          channelState.channels[id].archived = true;
          saveChannels();
          fireOnUpdate();
        }
        return;
      }

      channelState.channels[id] = {
        id,
        name:        meta.name,
        description: meta.about || '',
        type:        meta.ciphernet.type || 'public',
        ownerFp:     meta.ciphernet.ownerFp || '',
        ownerPub:    meta.ciphernet.ownerPub || '',
        created:     kind40Event.created_at * 1000,
        archived:    meta.ciphernet.archived || false,
        passphrase:  meta.ciphernet.passphrase || false,
        admins:      meta.ciphernet.admins || [],
        banned:      meta.ciphernet.banned || [],
        nostrId:     id,
      };

      saveChannels();
      fireOnUpdate();
    } catch { /* malformed event — ignore */ }
  },

  // ── Restore passphrase keys on login ────────────────────

  async restoreKeys() {
    for (const id of channelState.joined) {
      const pass = loadChannelPassphrase(id);
      if (pass) {
        try {
          channelState.activeKeys[id] = await deriveChannelAESKey(pass, id);
        } catch { /* passphrase may have changed */ }
      }
    }
  },

  // ── Publish this channel to Nostr ───────────────────────

  publishToNostr,
};

// Expose globally
window.CipherChannels = Channels;
