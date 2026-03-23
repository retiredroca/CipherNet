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
//   owner   — created channel, holds admin keypair
//   admin   — promoted by owner, can ban/set passphrase
//   member  — has write passphrase
//   guest   — can read unencrypted channels, cannot write
//   banned  — fingerprint on ban list, messages ignored
//
// Nostr kinds used:
//   40  — channel creation metadata
//   41  — channel metadata update
//   42  — channel message
//   9733 — private: channel invite token (NIP-57 inspired)
//   9734 — channel admin event (ban, promote, passphrase update)
// ═══════════════════════════════════════════════════════

// ── Storage keys ─────────────────────────────────────────
const CHANNELS_KEY  = 'cipher_channels_v2';
const JOINED_KEY    = 'cipher_joined_channels';
const INVITES_KEY   = 'cipher_channel_invites';

// ── Channel schema ───────────────────────────────────────
/*
Channel object:
{
  id:          string,   // SHA-256 of "ciphernet-channel-v2:<name>:<ownerFp>"
  name:        string,   // display name
  description: string,
  type:        'public' | 'private',
  ownerFp:     string,   // CIPHER//NET fingerprint of owner
  ownerPub:    string,   // owner public key PEM (for verifying admin events)
  created:     number,   // timestamp ms
  archived:    boolean,

  // Passphrase config
  passphrase:  boolean,  // true = write requires passphrase
  // actual passphrase key is stored in cipher_chan_key_<id>

  // Role lists (fingerprints)
  admins:      string[],
  banned:      string[],

  // Nostr
  nostrId:     string | null,  // Nostr event ID of kind 40 creation
}
*/

// ── In-memory state ──────────────────────────────────────
const channelState = {
  channels:    {},   // id → Channel
  joined:      [],   // [id, ...] ordered list of joined channel IDs
  activeKeys:  {},   // id → CryptoKey (AES-GCM write key)
  subs:        {},   // id → nostrSubId
  onUpdate:    null, // callback() when channel list changes
};

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

// ── Channel ID derivation ────────────────────────────────

async function deriveChannelId(name, ownerFp) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode('ciphernet-channel-v2:' + name + ':' + ownerFp)
  );
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
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
  localStorage.removeItem('cipher_chan_key_'  + channelId);
  delete channelState.activeKeys[channelId];
}

// ── Admin event signing ──────────────────────────────────
// Admin events are signed with the owner/admin's CIPHER//NET signing key
// and stored as Nostr kind 9734 events OR in localStorage for offline use.

async function signAdminEvent(payload, signingKey, algo) {
  const str = JSON.stringify(payload);
  const sig  = await signData(str, signingKey, algo);
  return { payload, sig, ts: Date.now() };
}

async function verifyAdminEvent(event, pubKeyPem, algo) {
  try {
    const str = JSON.stringify(event.payload);
    return verifyData(str, event.sig, pubKeyPem, algo);
  } catch { return false; }
}

// ── Invite tokens ────────────────────────────────────────

async function generateInvite(channelId, inviterFp, inviterSigningKey, inviterAlgo, passphrase) {
  const token = {
    channelId,
    inviterFp,
    passphrase: passphrase || null,
    expires:    Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
    nonce:      Array.from(crypto.getRandomValues(new Uint8Array(8)))
                  .map(b => b.toString(16).padStart(2,'0')).join(''),
  };
  const str = JSON.stringify(token);
  const sig  = await signData(str, inviterSigningKey, inviterAlgo);
  const invite = { token, sig };
  return btoa(JSON.stringify(invite));
}

async function parseInvite(b64) {
  try {
    const invite  = JSON.parse(atob(b64));
    const { token, sig } = invite;
    if (Date.now() > token.expires) throw new Error('Invite expired');
    return { token, sig, raw: invite };
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

  get(id) { return channelState.channels[id] || null; },

  getRole(channelId, fingerprint) {
    const ch = channelState.channels[channelId];
    if (!ch) return null;
    if (ch.banned.includes(fingerprint))  return 'banned';
    if (ch.ownerFp === fingerprint)        return 'owner';
    if (ch.admins.includes(fingerprint))   return 'admin';
    if (channelState.joined.includes(channelId)) {
      const pass = loadChannelPassphrase(channelId);
      return pass ? 'member' : 'guest';
    }
    return 'guest';
  },

  canWrite(channelId, fingerprint) {
    const role = this.getRole(channelId, fingerprint);
    if (role === 'banned') return false;
    if (!channelState.channels[channelId]) return false;
    const ch = channelState.channels[channelId];
    if (!ch.passphrase) return role !== null; // open channel — anyone can write
    // passphrase channel — need write key
    return !!channelState.activeKeys[channelId];
  },

  canRead(channelId) {
    const ch = channelState.channels[channelId];
    if (!ch) return false;
    if (!ch.passphrase) return true; // no passphrase = anyone reads
    return !!channelState.activeKeys[channelId];
  },

  getActiveKey(channelId) {
    return channelState.activeKeys[channelId] || null;
  },

  // ── Create channel ──────────────────────────────────────

  async create(opts, ownerFp, ownerPubKeyPem, ownerSigningKey, ownerAlgo) {
    const { name, description = '', type = 'public', passphrase = null } = opts;
    if (!name || !/^[a-zA-Z0-9_\-\s]{1,64}$/.test(name))
      throw new Error('Channel name: 1-64 chars, letters/numbers/spaces/_/-');

    const id = await deriveChannelId(name.trim(), ownerFp);
    if (channelState.channels[id])
      throw new Error('A channel with this name already exists for your identity');

    const ch = {
      id, name: name.trim(), description, type,
      ownerFp, ownerPub: ownerPubKeyPem,
      created: Date.now(), archived: false,
      passphrase: !!passphrase,
      admins: [], banned: [],
      nostrId: null,
    };

    channelState.channels[id] = ch;
    if (!channelState.joined.includes(id)) channelState.joined.unshift(id);

    if (passphrase) {
      saveChannelKey(id, passphrase);
      // Derive and cache the AES key
      channelState.activeKeys[id] = await deriveChannelAESKey(passphrase, id);
    }

    saveChannels();

    // Publish to Nostr if available
    if (window.CipherNostr && window.CipherNostr.isReady() && type === 'public') {
      try {
        const nostrId = await publishChannelCreation(ch);
        ch.nostrId = nostrId;
        saveChannels();
      } catch (e) { console.warn('[Channels] Nostr publish failed:', e.message); }
    }

    if (channelState.onUpdate) channelState.onUpdate();
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
    } else if (!ch.passphrase) {
      // No passphrase required — guest/read mode
    }

    saveChannels();
    if (channelState.onUpdate) channelState.onUpdate();
    return ch;
  },

  // ── Join via invite ─────────────────────────────────────

  async joinViaInvite(b64Invite, inviterPubKeyPem, inviterAlgo) {
    const { token, sig } = await parseInvite(b64Invite);
    // Verify invite signature
    const tokenStr = JSON.stringify(token);
    const valid    = await verifyData(tokenStr, sig, inviterPubKeyPem, inviterAlgo);
    if (!valid) throw new Error('Invite signature invalid');

    const ch = channelState.channels[token.channelId];
    if (!ch) throw new Error('Channel not found — make sure the channel creator is in your user registry');

    return this.join(token.channelId, token.passphrase);
  },

  // ── Leave channel ───────────────────────────────────────

  leave(channelId) {
    channelState.joined = channelState.joined.filter(id => id !== channelId);
    clearChannelKey(channelId);
    saveChannels();
    if (channelState.onUpdate) channelState.onUpdate();
  },

  // ── Update passphrase (owner/admin only) ────────────────

  async setPassphrase(channelId, newPassphrase, actorFp, actorSigningKey, actorAlgo) {
    const ch   = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    const role = this.getRole(channelId, actorFp);
    if (role !== 'owner' && role !== 'admin')
      throw new Error('Only owner or admin can change passphrase');

    ch.passphrase = !!newPassphrase;
    if (newPassphrase) {
      saveChannelKey(channelId, newPassphrase);
      channelState.activeKeys[channelId] = await deriveChannelAESKey(newPassphrase, channelId);
    } else {
      clearChannelKey(channelId);
    }

    // Sign admin event
    const event = await signAdminEvent(
      { action: 'set_passphrase', channelId, hasPassphrase: ch.passphrase, ts: Date.now() },
      actorSigningKey, actorAlgo
    );
    publishAdminEvent(channelId, event);

    // Publish updated metadata to Nostr
    if (window.CipherNostr && window.CipherNostr.isReady())
      publishChannelUpdate(ch).catch(() => {});

    saveChannels();
    if (channelState.onUpdate) channelState.onUpdate();
  },

  // ── Ban / unban (owner only) ────────────────────────────

  async ban(channelId, targetFp, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (this.getRole(channelId, actorFp) !== 'owner')
      throw new Error('Only owner can ban users');
    if (targetFp === actorFp) throw new Error('Cannot ban yourself');

    if (!ch.banned.includes(targetFp)) ch.banned.push(targetFp);
    ch.admins = ch.admins.filter(f => f !== targetFp);

    const event = await signAdminEvent(
      { action: 'ban', channelId, targetFp, ts: Date.now() },
      actorSigningKey, actorAlgo
    );
    publishAdminEvent(channelId, event);

    saveChannels();
    if (channelState.onUpdate) channelState.onUpdate();
  },

  async unban(channelId, targetFp, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (this.getRole(channelId, actorFp) !== 'owner')
      throw new Error('Only owner can unban');

    ch.banned = ch.banned.filter(f => f !== targetFp);

    const event = await signAdminEvent(
      { action: 'unban', channelId, targetFp, ts: Date.now() },
      actorSigningKey, actorAlgo
    );
    publishAdminEvent(channelId, event);

    saveChannels();
    if (channelState.onUpdate) channelState.onUpdate();
  },

  // ── Promote / demote admin (owner only) ─────────────────

  async promote(channelId, targetFp, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (this.getRole(channelId, actorFp) !== 'owner')
      throw new Error('Only owner can promote admins');
    if (!ch.admins.includes(targetFp)) ch.admins.push(targetFp);
    ch.banned = ch.banned.filter(f => f !== targetFp);

    const event = await signAdminEvent(
      { action: 'promote', channelId, targetFp, ts: Date.now() },
      actorSigningKey, actorAlgo
    );
    publishAdminEvent(channelId, event);

    saveChannels();
    if (channelState.onUpdate) channelState.onUpdate();
  },

  async demote(channelId, targetFp, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (this.getRole(channelId, actorFp) !== 'owner')
      throw new Error('Only owner can demote admins');
    ch.admins = ch.admins.filter(f => f !== targetFp);

    const event = await signAdminEvent(
      { action: 'demote', channelId, targetFp, ts: Date.now() },
      actorSigningKey, actorAlgo
    );
    publishAdminEvent(channelId, event);

    saveChannels();
    if (channelState.onUpdate) channelState.onUpdate();
  },

  // ── Archive / delete (owner only) ───────────────────────

  async archive(channelId, actorFp, actorSigningKey, actorAlgo) {
    const ch = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    if (ch.ownerFp !== actorFp) throw new Error('Only owner can archive channel');

    ch.archived = true;
    channelState.joined = channelState.joined.filter(id => id !== channelId);

    const event = await signAdminEvent(
      { action: 'archive', channelId, ts: Date.now() },
      actorSigningKey, actorAlgo
    );
    publishAdminEvent(channelId, event);

    if (window.CipherNostr && window.CipherNostr.isReady())
      publishChannelUpdate(ch).catch(() => {});

    saveChannels();
    if (channelState.onUpdate) channelState.onUpdate();
  },

  // ── Generate invite ──────────────────────────────────────

  async invite(channelId, actorFp, actorSigningKey, actorAlgo) {
    const ch   = channelState.channels[channelId];
    if (!ch) throw new Error('Channel not found');
    const role = this.getRole(channelId, actorFp);
    if (role !== 'owner' && role !== 'admin')
      throw new Error('Only owner or admin can generate invites');

    const passphrase = loadChannelPassphrase(channelId);
    return generateInvite(channelId, actorFp, actorSigningKey, actorAlgo, passphrase);
  },

  // ── Import channel from Nostr event ─────────────────────

  async importFromNostr(kind40Event) {
    try {
      const meta = JSON.parse(kind40Event.content);
      if (!meta.name || !meta.ciphernet) return; // not a CIPHER//NET channel

      const id = kind40Event.id;
      if (channelState.channels[id]) return; // already known

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
      if (channelState.onUpdate) channelState.onUpdate();
    } catch { /* invalid event */ }
  },

  // ── Set active key for channel (called when passphrase entered) ──

  async activateKey(channelId, passphrase) {
    try {
      const key = await deriveChannelAESKey(passphrase, channelId);
      channelState.activeKeys[channelId] = key;
      saveChannelKey(channelId, passphrase);
      return true;
    } catch { return false; }
  },

  // ── Restore saved keys on login ──────────────────────────

  async restoreKeys() {
    for (const id of channelState.joined) {
      const pass = loadChannelPassphrase(id);
      if (pass) {
        try {
          channelState.activeKeys[id] = await deriveChannelAESKey(pass, id);
        } catch { /* key derivation failed, passphrase may have changed */ }
      }
    }
  },

  // ── Subscribe to Nostr channel events ───────────────────

  async subscribeNostr() {
    if (!window.CipherNostr || !window.CipherNostr.isReady()) return;
    for (const id of channelState.joined) {
      if (channelState.subs[id]) continue;
      channelState.subs[id] = await window.CipherNostr.subscribeChannel(
        id, (event) => handleIncomingNostrMessage(id, event)
      );
    }
    // Subscribe to public channel discovery
    channelState.subs['discovery'] = await subscribeChannelDiscovery();
  },

  // Return storage key for messages
  msgKey(channelId) { return 'cipher_msgs_ch_' + channelId; },
};

// ── AES key derivation (same as before but keyed to channel ID) ──

async function deriveChannelAESKey(passphrase, channelId) {
  const enc  = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const salt = await crypto.subtle.digest('SHA-256', enc.encode('ciphernet-channel-v2:' + channelId));
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

// ── Nostr publish helpers ────────────────────────────────

async function publishChannelCreation(ch) {
  if (!window.CipherNostr) return null;
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
      archived:   false,
      version:    2,
    },
  });
  // kind 40 — channel creation
  return window.CipherNostr.publishRaw(40, content, []);
}

async function publishChannelUpdate(ch) {
  if (!window.CipherNostr || !ch.nostrId) return;
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
      archived:   ch.archived,
      version:    2,
    },
  });
  // kind 41 — channel metadata update
  return window.CipherNostr.publishRaw(41, content, [['e', ch.nostrId]]);
}

function publishAdminEvent(channelId, event) {
  // Store locally
  const key  = 'cipher_chan_admin_' + channelId;
  const list = JSON.parse(localStorage.getItem(key) || '[]');
  list.push(event);
  localStorage.setItem(key, JSON.stringify(list));
  // Publish to Nostr (kind 9734) if available
  if (window.CipherNostr && window.CipherNostr.isReady()) {
    const content = JSON.stringify(event);
    window.CipherNostr.publishRaw(9734, content, [['e', channelId]]).catch(() => {});
  }
}

async function subscribeChannelDiscovery() {
  if (!window.CipherNostr) return null;
  return window.CipherNostr.subscribeRaw({ kinds: [40] }, async (event) => {
    await Channels.importFromNostr(event);
  });
}

async function handleIncomingNostrMessage(channelId, event) {
  const ch = Channels.get(channelId);
  if (!ch) return;
  // Check ban list
  const users = JSON.parse(localStorage.getItem('cipher_users') || '{}');
  const sender = Object.values(users).find(u => u.nostrPub === event.pubkey);
  if (sender && ch.banned.includes(sender.fingerprint)) return;
  // Pass to app.js handler
  if (window._channelNostrHandler) window._channelNostrHandler(channelId, event);
}

// Expose globally
window.CipherChannels = Channels;
