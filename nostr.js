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

// NIP-28 channel IDs — one per CIPHER//NET channel
const CHANNEL_IDS = {};

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

// ── Load secp256k1 from esm.sh ───────────────────────────
let _schnorr = null;

async function loadSecp256k1() {
  if (_schnorr) return _schnorr;
  const mod = await import('https://esm.sh/@noble/curves@1.4.0/secp256k1.js');
  _schnorr = mod.schnorr || (mod.secp256k1 && mod.secp256k1.schnorr);
  if (!_schnorr) throw new Error('secp256k1 schnorr not found in @noble/curves');
  return _schnorr;
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
  const schnorr       = await loadSecp256k1();
  const sharedPoint   = schnorr.getSharedSecret(hexToBytes(senderPrivHex), '02' + recipientPubHex);
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
  const schnorr     = await loadSecp256k1();
  const payload     = Uint8Array.from(atob(b64payload), c => c.charCodeAt(0));
  if (payload[0] !== 2) throw new Error('Unsupported NIP-44 version');
  const salt        = payload.slice(1, 33);
  const iv          = payload.slice(33, 45);
  const ct          = payload.slice(45);
  const sharedPoint = schnorr.getSharedSecret(hexToBytes(recipientPrivHex), '02' + senderPubHex);
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

function getRelayList() {
  try {
    const stored = localStorage.getItem('cipher_nostr_relays');
    return stored ? JSON.parse(stored) : [...DEFAULT_RELAYS];
  } catch { return [...DEFAULT_RELAYS]; }
}

function saveRelayList(relays) {
  localStorage.setItem('cipher_nostr_relays', JSON.stringify(relays));
}

function connectRelay(url) {
  if (nostrState.relays[url] &&
      nostrState.relays[url].ws &&
      nostrState.relays[url].ws.readyState <= 1) return; // already connected/connecting

  let ws;
  try { ws = new WebSocket(url); } catch (e) {
    console.warn('[Nostr] Cannot connect to', url, e.message);
    setRelayStatus(url, 'error');
    return;
  }

  nostrState.relays[url] = { ws, status: 'connecting', subIds: new Set() };
  setRelayStatus(url, 'connecting');

  ws.onopen = () => {
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
    // Reconnect after 5s
    setTimeout(() => connectRelay(url), 5000);
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
    if (sub && sub.onEvent) sub.onEvent(event, url);
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

function saveNostrKeys(privKey, pubKey) {
  localStorage.setItem('cipher_nostr_priv', btoa(String.fromCharCode(...privKey)));
  localStorage.setItem('cipher_nostr_pub', pubKey);
}

function loadNostrKeys() {
  const priv = localStorage.getItem('cipher_nostr_priv');
  const pub  = localStorage.getItem('cipher_nostr_pub');
  if (!priv || !pub) return null;
  return {
    privKey: Uint8Array.from(atob(priv), c => c.charCodeAt(0)),
    pubKey:  pub,
  };
}

// ── NIP-28 channel ID derivation ────────────────────────
// Each CIPHER//NET channel maps to a deterministic Nostr channel ID

async function getChannelId(channelName) {
  if (CHANNEL_IDS[channelName]) return CHANNEL_IDS[channelName];
  const id = await sha256Hex('ciphernet-channel-v1:' + channelName);
  CHANNEL_IDS[channelName] = id;
  return id;
}

// ── Public API ───────────────────────────────────────────

const Nostr = {

  // Initialize: load or generate transport keypair, connect to relays
  async init(onMessage, onStatus) {
    nostrState.onMessage = onMessage;
    nostrState.onStatus  = onStatus;

    // Load or generate secp256k1 transport keypair
    let keys = loadNostrKeys();
    if (!keys) {
      try {
        keys = await generateNostrKeypair();
        saveNostrKeys(keys.privKey, keys.pubKey);
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

  addRelay(url) {
    const list = getRelayList();
    if (!list.includes(url)) { list.push(url); saveRelayList(list); }
    connectRelay(url);
  },

  removeRelay(url) {
    const list = getRelayList().filter(u => u !== url);
    saveRelayList(list);
    disconnectRelay(url);
  },

  // Publish a CIPHER//NET channel message via NIP-28 (kind 42)
  async publishChannelMessage(channelName, ciphertextPayload) {
    if (!nostrState.privKey) throw new Error('Nostr not initialized');
    const chanId = await getChannelId(channelName);
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
  async subscribeChannel(channelName, onEvent, since) {
    const chanId = await getChannelId(channelName);
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
