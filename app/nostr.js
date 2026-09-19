/*
 * CIPHER//NET — Self-hosted, end-to-end encrypted chat
 * Copyright (C) 2024 retiredroca
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Source code: https://github.com/retiredroca/CipherNet
 */
'use strict';

// ═══════════════════════════════════════════════════════
// CIPHER//NET — nostr.js
// Nostr transport layer: NIP-28 channels + NIP-44 encrypted DMs
// Identities: secp256k1 companion keys (transport only)
// Payload:    CIPHER//NET AES-256-GCM envelopes (unchanged)
// ═══════════════════════════════════════════════════════

// ── Default relays ──────────────────────────────────────
const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://relay.nostr.band',
  'wss://nos.lol',
  'wss://relay.snort.social',
  // .onion relays (Tor Browser / system Tor)
  'ws://jgqaglhztewuqpfbmxcwbclsuddprvqvxcjwkiohbkvgkoxjmbsrj6qd.onion',
];

// ── State ────────────────────────────────────────────────
const nostrState = {
  privKey:    null,   // secp256k1 private key (Uint8Array, 32 bytes)
  pubKey:     null,   // secp256k1 public key hex (64 chars, x-only)
  relays:     {},     // url → { ws, status, subIds }
  subs:       {},     // subId → { filters, onEvent }
  subCounter: 0,
  onMessage:  null,   // callback(event, decryptedPayload)
  onStatus:   null,   // callback(url, status)
};

// ── Load secp256k1 (vendored bundle preferred, esm.sh fallback) ──
let _schnorr = null;
let _secp256k1 = null;

function vendoredSecp256k1() {
  if (window.nobleSecp256k1) {
    _schnorr    = _schnorr    || window.nobleSecp256k1.schnorr || null;
    _secp256k1  = _secp256k1  || window.nobleSecp256k1.secp256k1 || null;
  }
}

async function loadSecp256k1() {
  if (_schnorr) return _schnorr;
  vendoredSecp256k1();
  if (_schnorr) return _schnorr;
  const mod = await import('https://esm.sh/@noble/curves@1.4.0/secp256k1.js');
  _schnorr   = mod.schnorr || (mod.secp256k1 && mod.secp256k1.schnorr);
  _secp256k1 = mod.secp256k1 || null;
  if (!_schnorr) throw new Error('secp256k1 schnorr not found in @noble/curves');
  return _schnorr;
}

async function loadCurve() {
  if (_secp256k1) return _secp256k1;
  vendoredSecp256k1();
  if (_secp256k1) return _secp256k1;
  await loadSecp256k1();
  if (!_secp256k1) throw new Error('secp256k1 curve (ECDH) not available');
  return _secp256k1;
}

async function ecdhSharedPoint(privHex, pubHex) {
  const curve = await loadCurve();
  if (typeof curve.getSharedSecret === 'function') {
    return curve.getSharedSecret(hexToBytes(privHex), pubHex); // projectable
  }
  // Fallback: ECDH via ProjectivePoint multiply
  const pt  = curve.ProjectivePoint.fromHex(pubHex);
  const d   = curve.utils.normPrivateKeyToScalar(hexToBytes(privHex));
  return pt.multiply(d).toRawBytes(true);
}

// ── secp256k1 helpers ────────────────────────────────────

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++)
    arr[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return arr;
}

async function generateNostrKeypair() {
  const schnorr = await loadSecp256k1();
  const priv    = crypto.getRandomValues(new Uint8Array(32));
  const pub     = schnorr.getPublicKey(priv);  // 32-byte x-only
  return { privKey: priv, pubKey: bytesToHex(pub) };
}

async function nostrSign(eventHash, privKey) {
  const schnorr = await loadSecp256k1();
  const sig     = await schnorr.sign(eventHash, privKey);
  return bytesToHex(sig);
}

async function nostrVerify(sig, hash, pubKeyHex) {
  try {
    const schnorr = await loadSecp256k1();
    return schnorr.verify(hexToBytes(sig), hexToBytes(hash), hexToBytes(pubKeyHex));
  } catch { return false; }
}

// ── Nostr event construction ─────────────────────────────

async function sha256Hex(str) {
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return bytesToHex(new Uint8Array(buf));
}

async function buildEvent(kind, content, tags, privKey, pubKeyHex) {
  const created_at = Math.floor(Date.now() / 1000);
  const event = {
    pubkey:     pubKeyHex,
    created_at,
    kind,
    tags,
    content,
  };
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
  const id  = await sha256Hex(serialized);
  const sig = await nostrSign(hexToBytes(id), privKey);
  return { ...event, id, sig };
}

// ── NIP-44 encryption (v2) ───────────────────────────────
// Used for DM transport layer (inner payload is already CIPHER//NET encrypted)

async function nip44Encrypt(plaintext, senderPrivHex, recipientPubHex) {
  const sharedPoint   = await ecdhSharedPoint(senderPrivHex, '02' + recipientPubHex);
  const sharedX       = sharedPoint.slice(1, 33); // x-coordinate only
  const keyMaterial   = await crypto.subtle.importKey('raw', sharedX, 'HKDF', false, ['deriveKey']);
  const salt          = crypto.getRandomValues(new Uint8Array(32));
  const aesKey        = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('nip44-v2') },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const iv        = crypto.getRandomValues(new Uint8Array(12));
  const ct        = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext));
  const payload   = new Uint8Array(1 + 32 + 12 + ct.byteLength);
  payload[0] = 2; // version
  payload.set(salt, 1);
  payload.set(iv, 33);
  payload.set(new Uint8Array(ct), 45);
  return btoa(String.fromCharCode(...payload));
}

async function nip44Decrypt(b64payload, recipientPrivHex, senderPubHex) {
  const payload     = Uint8Array.from(atob(b64payload), c => c.charCodeAt(0));
  if (payload[0] !== 2) throw new Error('Unsupported NIP-44 version');
  const salt        = payload.slice(1, 33);
  const iv          = payload.slice(33, 45);
  const ct          = payload.slice(45);
  const sharedPoint = await ecdhSharedPoint(recipientPrivHex, '02' + senderPubHex);
  const sharedX     = sharedPoint.slice(1, 33);
  const keyMaterial = await crypto.subtle.importKey('raw', sharedX, 'HKDF', false, ['deriveKey']);
  const aesKey      = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('nip44-v2') },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return new TextDecoder().decode(plain);
}

// ── Relay management ─────────────────────────────────────
// Static (built-in) relays always exist and can only be DISABLED, never
// removed. User-added relays can be toggled and removed. The enabled set
// used for connecting is configuredRelays − disabledRelays.
//
//   cipher_nostr_relays        → array, all configured relays (defaults + user-added)
//   cipher_nostr_disabled      → array, URLs currently toggled off

const RELAY_CONFIG_KEY   = 'cipher_nostr_relays';
const RELAY_DISABLED_KEY = 'cipher_nostr_disabled';

function isStaticRelay(url) {
  return DEFAULT_RELAYS.includes(url);
}

function getDisabledRelays() {
  try {
    const d = JSON.parse(localStorage.getItem(RELAY_DISABLED_KEY) || '[]');
    return Array.isArray(d) ? d : [];
  } catch { return []; }
}

function saveDisabledRelays(list) {
  localStorage.setItem(RELAY_DISABLED_KEY, JSON.stringify(list));
}

// All configured relays: static defaults are always present (a list left
// empty by older builds self-heals back to defaults).
function getConfiguredRelays() {
  try {
    const stored = JSON.parse(localStorage.getItem(RELAY_CONFIG_KEY) || '[]');
    const configured = Array.isArray(stored) ? stored : [];
    return Array.from(new Set([...configured, ...DEFAULT_RELAYS]));
  } catch { return [...DEFAULT_RELAYS]; }
}

function saveRelayList(relays) {
  localStorage.setItem(RELAY_CONFIG_KEY, JSON.stringify(relays));
}

// Enabled relays — the ones actually connected/used for traffic.
function getRelayList() {
  const enabled  = getConfiguredRelays();
  const disabled = new Set(getDisabledRelays());
  return enabled.filter(u => !disabled.has(u));
}

function connectRelay(url) {
  const existing = nostrState.relays[url];
  if (existing && existing.ws && existing.ws.readyState <= 1) return; // already connected/connecting
  if (existing && existing.reconnectTimer) return; // a reconnect is already scheduled

  let ws;
  try { ws = new WebSocket(url); } catch (e) {
    console.warn('[Nostr] Cannot connect to', url, e.message);
    setRelayStatus(url, 'error');
    return;
  }

  nostrState.relays[url] = { ...existing, ws, status: 'connecting', subIds: new Set(), reconnectDelay: existing?.reconnectDelay || 5000 };
  setRelayStatus(url, 'connecting');

  ws.onopen = () => {
    const relay = nostrState.relays[url];
    if (relay) relay.reconnectDelay = 5000; // reset backoff after a successful connection
    setRelayStatus(url, 'connected');
    console.log('[Nostr] Connected to', url);
    // Re-subscribe all active subscriptions
    for (const [subId, sub] of Object.entries(nostrState.subs)) {
      ws.send(JSON.stringify(['REQ', subId, ...sub.filters]));
    }
  };

  ws.onmessage = e => {
    try { handleRelayMessage(url, JSON.parse(e.data)); }
    catch (err) { console.warn('[Nostr] Parse error from', url, err); }
  };

  ws.onerror = () => setRelayStatus(url, 'error');
  ws.onclose = () => {
    setRelayStatus(url, 'disconnected');
    const relay = nostrState.relays[url];
    if (!relay) return;
    const delay = relay.reconnectDelay || 5000;
    relay.reconnectDelay = Math.min(delay * 1.5, 30000); // exponential backoff, capped at 30s
    clearTimeout(relay.reconnectTimer);
    relay.reconnectTimer = setTimeout(() => {
      relay.reconnectTimer = null;
      connectRelay(url);
    }, delay);
  };
}

function disconnectRelay(url) {
  const relay = nostrState.relays[url];
  if (relay && relay.ws) {
    relay.ws.onclose = null; // suppress auto-reconnect
    relay.ws.close();
    delete nostrState.relays[url];
  }
  setRelayStatus(url, 'disconnected');
}

function setRelayStatus(url, status) {
  if (nostrState.relays[url]) nostrState.relays[url].status = status;
  if (nostrState.onStatus) nostrState.onStatus(url, status);
}

function handleRelayMessage(url, msg) {
  if (!Array.isArray(msg)) return;
  const [type, ...args] = msg;
  if (type === 'EVENT') {
    const [subId, event] = args;
    const sub = nostrState.subs[subId];
    if (sub && sub.onEvent) {
      nostrVerify(event.sig, event.id, event.pubkey).then(valid => {
        if (valid) sub.onEvent(event, url);
        else console.warn('[Nostr] Rejected event with invalid signature from', url);
      }).catch(err => console.warn('[Nostr] Verify error from', url, err));
    }
  } else if (type === 'NOTICE') {
    console.log('[Nostr] NOTICE from', url, args[0]);
  } else if (type === 'EOSE') {
    // End of stored events — subscription is now live
  }
}

function publishToRelays(event) {
  let published = 0;
  for (const [url, relay] of Object.entries(nostrState.relays)) {
    if (relay.ws && relay.ws.readyState === WebSocket.OPEN) {
      relay.ws.send(JSON.stringify(['EVENT', event]));
      published++;
    }
  }
  return published;
}

function subscribeRelays(filters, onEvent) {
  const subId = 'cipher-' + (++nostrState.subCounter);
  nostrState.subs[subId] = { filters: Array.isArray(filters) ? filters : [filters], onEvent };
  for (const relay of Object.values(nostrState.relays)) {
    if (relay.ws && relay.ws.readyState === WebSocket.OPEN) {
      relay.ws.send(JSON.stringify(['REQ', subId, ...nostrState.subs[subId].filters]));
    }
  }
  return subId;
}

function unsubscribeRelays(subId) {
  if (!nostrState.subs[subId]) return;
  delete nostrState.subs[subId];
  for (const relay of Object.values(nostrState.relays)) {
    if (relay.ws && relay.ws.readyState === WebSocket.OPEN)
      relay.ws.send(JSON.stringify(['CLOSE', subId]));
  }
}

// ── Nostr key persistence ────────────────────────────────
// Transport private key is stored AES-256-GCM wrapped with a key derived
// from the CIPHER//NET signing identity. No plaintext at rest. If no
// identity is available the key is kept in memory only (ephemeral).

const NOSTR_WRAP_KEY = 'cipher_nostr_wrap';

async function saveNostrKeys(privKey, pubKey, identity) {
  nostrState.privKey = privKey;
  nostrState.pubKey  = pubKey;
  if (identity && identity.signingKey && identity.algo && window.CipherNet.Crypto) {
    try {
      const wrapped = await window.CipherNet.Crypto.wrapWithIdentityKey(identity.signingKey, identity.algo, privKey);
      localStorage.setItem(NOSTR_WRAP_KEY, JSON.stringify({ pub: pubKey, wrapped }));
      localStorage.removeItem('cipher_nostr_priv');
      localStorage.removeItem('cipher_nostr_pub');
      return;
    } catch (e) { console.warn('[Nostr] Key wrap failed — keeping in memory only:', e.message); }
  }
  localStorage.removeItem(NOSTR_WRAP_KEY);
  localStorage.removeItem('cipher_nostr_priv');
  localStorage.removeItem('cipher_nostr_pub');
}

async function loadNostrKeys(identity) {
  if (!identity || !identity.signingKey || !identity.algo || !window.CipherNet.Crypto) return null;
  const stored = localStorage.getItem(NOSTR_WRAP_KEY);
  if (!stored) return null;
  try {
    const obj    = JSON.parse(stored);
    const priv   = await window.CipherNet.Crypto.unwrapWithIdentityKey(identity.signingKey, identity.algo, obj.wrapped);
    if (!priv || priv.length !== 32) return null;
    return { privKey: priv, pubKey: obj.pub };
  } catch { return null; }
}

// ── NIP-28 channel identifiers ────────────────────────────
// A CIPHER//NET channel's identifier IS its Nostr channel id.
// Locally created and discovery-imported channels derive the same
// SHA-256 ("ciphernet-channel-v2:<name>:<ownerFp>") value from the
// public kind-40 metadata, so every participant tags messages with
// the identical id. No separate legacy derivation.

function getChannelId(channelId) {
  return channelId;
}

// ── Public API ───────────────────────────────────────────

const Nostr = {

  // Initialize: load or generate transport keypair, connect to relays
  async init(onMessage, onStatus, identity) {
    nostrState.onMessage = onMessage;
    nostrState.onStatus  = onStatus;

    // Load or generate secp256k1 transport keypair (encrypted at rest)
    let keys = await loadNostrKeys(identity);
    if (!keys) {
      try {
        keys = await generateNostrKeypair();
        await saveNostrKeys(keys.privKey, keys.pubKey, identity);
      } catch (e) {
        console.warn('[Nostr] secp256k1 not available yet:', e.message);
        return false;
      }
    }
    nostrState.privKey = keys.privKey;
    nostrState.pubKey  = keys.pubKey;
    console.log('[Nostr] Transport pubkey:', nostrState.pubKey.slice(0,16) + '...');

    // Connect to all relays
    for (const url of getRelayList()) connectRelay(url);
    return true;
  },

  isReady() {
    return !!nostrState.pubKey && Object.values(nostrState.relays)
      .some(r => r.ws && r.ws.readyState === WebSocket.OPEN);
  },

  getStatus() {
    return Object.fromEntries(
      Object.entries(nostrState.relays).map(([url, r]) => [url, r.status])
    );
  },

  getRelayList,
  saveRelayList,
  getConfiguredRelays,
  isStaticRelay,
  isRelayEnabled(url) {
    return !getDisabledRelays().includes(url);
  },

  addRelay(url) {
    const list = getConfiguredRelays();
    if (!list.includes(url)) { list.push(url); saveRelayList(list); }
    this.toggleRelay(url, true); // ensure enabled then connect
  },

  toggleRelay(url, enabled) {
    const disabled = getDisabledRelays().filter(u => u !== url);
    if (!enabled) disabled.push(url);
    saveDisabledRelays(Array.from(new Set(disabled)));
    if (enabled) connectRelay(url);
    else disconnectRelay(url);
  },

  // Static relays cannot be removed — only disabled.
  removeRelay(url) {
    if (isStaticRelay(url)) {
      console.warn('[Nostr] Static relay cannot be removed — disable it instead:', url);
      return false;
    }
    saveRelayList(getConfiguredRelays().filter(u => u !== url));
    saveDisabledRelays(getDisabledRelays().filter(u => u !== url));
    disconnectRelay(url);
    return true;
  },

  // Publish a CIPHER//NET channel message via NIP-28 (kind 42)
  async publishChannelMessage(channelId, ciphertextPayload) {
    if (!nostrState.privKey) throw new Error('Nostr not initialized');
    const chanId = getChannelId(channelId);
    const event  = await buildEvent(
      42,
      ciphertextPayload,           // already AES-256-GCM encrypted
      [['e', chanId, '', 'root']], // NIP-28 channel reference
      nostrState.privKey,
      nostrState.pubKey
    );
    const n = publishToRelays(event);
    if (n === 0) throw new Error('No relays connected');
    return event.id;
  },

  // Subscribe to a CIPHER//NET channel (NIP-28, kind 42)
  async subscribeChannel(channelId, onEvent, since) {
    const chanId = getChannelId(channelId);
    return subscribeRelays({
      kinds: [42],
      '#e':  [chanId],
      since: since || Math.floor(Date.now() / 1000) - 86400, // last 24h by default
    }, onEvent);
  },

  // Publish a CIPHER//NET DM via NIP-44 (kind 14, sealed in kind 1059)
  // Inner payload is already CIPHER//NET ML-KEM encrypted — NIP-44 adds Nostr transport privacy
  async publishDM(recipientPubKeyHex, ciphertextPayload) {
    if (!nostrState.privKey) throw new Error('Nostr not initialized');
    // Encrypt the payload with NIP-44 for transport privacy
    const privHex   = bytesToHex(nostrState.privKey);
    const encrypted = await nip44Encrypt(ciphertextPayload, privHex, recipientPubKeyHex);
    const rumor     = await buildEvent(14, encrypted, [['p', recipientPubKeyHex]], nostrState.privKey, nostrState.pubKey);
    // Seal: encrypt rumor JSON with NIP-44 to recipient
    const sealContent = await nip44Encrypt(JSON.stringify(rumor), privHex, recipientPubKeyHex);
    const seal        = await buildEvent(13, sealContent, [], nostrState.privKey, nostrState.pubKey);
    // Gift wrap: ephemeral key, kind 1059
    const ephemeral   = await generateNostrKeypair();
    const wrapContent = await nip44Encrypt(JSON.stringify(seal), bytesToHex(ephemeral.privKey), recipientPubKeyHex);
    const wrap        = await buildEvent(1059, wrapContent, [['p', recipientPubKeyHex]], ephemeral.privKey, ephemeral.pubKey);
    const n = publishToRelays(wrap);
    if (n === 0) throw new Error('No relays connected');
    return wrap.id;
  },

  // Subscribe to incoming DMs (kind 1059 gift wraps addressed to us)
  subscribeDMs(onEvent) {
    if (!nostrState.pubKey) return null;
    return subscribeRelays({
      kinds: [1059],
      '#p':  [nostrState.pubKey],
      since: Math.floor(Date.now() / 1000) - 86400 * 7, // last 7 days
    }, onEvent);
  },

  // Unwrap a received gift-wrapped DM
  async unwrapDM(wrapEvent) {
    const privHex = bytesToHex(nostrState.privKey);
    // Unwrap gift wrap (kind 1059)
    const sealJson = await nip44Decrypt(wrapEvent.content, privHex, wrapEvent.pubkey);
    const seal     = JSON.parse(sealJson);
    // Unwrap seal (kind 13)
    const rumorJson = await nip44Decrypt(seal.content, privHex, seal.pubkey);
    const rumor     = JSON.parse(rumorJson);
    // Decrypt NIP-44 transport layer to get CIPHER//NET payload
    const payload = await nip44Decrypt(rumor.content, privHex, rumor.pubkey);
    return { payload, senderPubKey: rumor.pubkey, ts: rumor.created_at };
  },

  // Store Nostr pubkey on user record for DM routing
  getTransportPubKey() { return nostrState.pubKey; },

  unsubscribe: unsubscribeRelays,

  // Raw event publish (for channel management events)
  async publishRaw(kind, content, tags) {
    if (!nostrState.privKey) throw new Error('Nostr not initialized');
    const event = await buildEvent(kind, content, tags, nostrState.privKey, nostrState.pubKey);
    const n = publishToRelays(event);
    if (n === 0) throw new Error('No relays connected');
    return event.id;
  },

  // Raw subscription (for channel discovery etc)
  async subscribeRaw(filter, onEvent) {
    return subscribeRelays(filter, onEvent);
  },
};

// Expose globally
window.CipherNostr = Nostr;
