window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';

  const B64CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  function b64Encode(bytes) {
    let out = '', i = 0;
    while (i < bytes.length) {
      const a = bytes[i++], b = bytes[i++], c = bytes[i++];
      out += B64CHARS[a >> 2]
          +  B64CHARS[((a & 3) << 4) | (b >> 4)]
          +  (b !== undefined ? B64CHARS[((b & 15) << 2) | (c >> 6)] : '=')
          +  (c !== undefined ? B64CHARS[c & 63] : '=');
    }
    return out;
  }
  function b64Decode(s) {
    s = s.replace(/[^A-Za-z0-9+/]/g, '');
    const lookup = new Uint8Array(256);
    for (let i = 0; i < B64CHARS.length; i++) lookup[B64CHARS.charCodeAt(i)] = i;
    const bytes = new Uint8Array(Math.floor(s.length * 3 / 4));
    let j = 0;
    for (let i = 0; i < s.length; i += 4) {
      const a = lookup[s.charCodeAt(i)], b = lookup[s.charCodeAt(i+1)],
            c = lookup[s.charCodeAt(i+2)], d = lookup[s.charCodeAt(i+3)];
      bytes[j++] = (a << 2) | (b >> 4);
      if (s[i+2] !== '=') bytes[j++] = ((b & 15) << 4) | (c >> 2);
      if (s[i+3] !== '=') bytes[j++] = ((c & 3)  << 6) | d;
    }
    return bytes.slice(0, j);
  }

  function toPem(buffer, label) {
    const b64 = b64Encode(new Uint8Array(buffer));
    return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----`;
  }

  function fromPem(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    return b64Decode(b64).buffer;
  }

  async function exportPrivPem(key) { return toPem(await crypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY'); }
  async function exportPubPem(key)  { return toPem(await crypto.subtle.exportKey('spki',  key), 'PUBLIC KEY'); }

  async function generateECDSA(namedCurve) {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify']);
  }

  async function generateRSAPSS() {
    return crypto.subtle.generateKey(
      { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
      true, ['sign', 'verify']
    );
  }

  async function importPrivateKey(pem) {
    pem = pem.trim();
    if (pem.includes('-----BEGIN PUBLIC KEY-----') || pem.includes('-----BEGIN EC PUBLIC KEY-----')) {
      throw new Error('You pasted your PUBLIC key. Paste the PRIVATE key instead (labeled "Signing Private Key").');
    }
    if (!pem.includes('-----BEGIN') || !pem.includes('PRIVATE KEY')) {
      throw new Error('This does not look like a private key. Copy the full PEM including -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY----- lines.');
    }

    const der = fromPem(pem);
    const errors = [];

    for (const curve of ['P-256', 'P-384']) {
      const sigAlg = { name: 'ECDSA', namedCurve: curve };

      try {
        const key = await crypto.subtle.importKey('pkcs8', der, sigAlg, true, ['sign']);
        const pub = await derivePublicFromPrivate(key, sigAlg);
        return { privateKey: key, publicKey: pub, algorithm: sigAlg };
      } catch (e) { errors.push('ECDSA-' + curve + '-direct: ' + (e.message || e)); }

      for (const importAs of ['ECDH', 'ECDSA']) {
        const importAlg = importAs === 'ECDH'
          ? { name: 'ECDH',  namedCurve: curve }
          : { name: 'ECDSA', namedCurve: curve };
        const importUsage = importAs === 'ECDH' ? ['deriveKey'] : ['sign', 'verify'];
        try {
          const tmp = await crypto.subtle.importKey('pkcs8', der, importAlg, true, importUsage);
          const jwk = await crypto.subtle.exportKey('jwk', tmp);
          delete jwk.key_ops;
          delete jwk.ext;
          const key = await crypto.subtle.importKey('jwk', jwk, sigAlg, true, ['sign']);
          const pub = await derivePublicFromPrivate(key, sigAlg);
          return { privateKey: key, publicKey: pub, algorithm: sigAlg };
        } catch (e) { errors.push('ECDSA-' + curve + '-via-' + importAs + '-JWK: ' + (e.message || e)); }
      }
    }

    try {
      const alg = { name: 'RSA-PSS', hash: 'SHA-256' };
      const key = await crypto.subtle.importKey('pkcs8', der, alg, true, ['sign']);
      const pub = await derivePublicFromPrivate(key, alg);
      return { privateKey: key, publicKey: pub, algorithm: alg };
    } catch (e) { errors.push('RSA-PSS: ' + (e.message || e)); }

    throw new Error('Could not import key. All attempts failed:\n' + errors.join('\n'));
  }

  async function derivePublicFromPrivate(privateKey, alg) {
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    ['d','p','q','dp','dq','qi','key_ops'].forEach(k => delete jwk[k]);
    const pubAlg = alg.name === 'ECDSA'
      ? { name: 'ECDSA', namedCurve: alg.namedCurve }
      : { name: 'RSA-PSS', hash: 'SHA-256' };
    return crypto.subtle.importKey('jwk', jwk, pubAlg, true, ['verify']);
  }

  async function fingerprint(pubKeyPem) {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pubKeyPem));
    return Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  function getSignAlg(algo) {
    if (!algo || algo.name === 'ECDSA') {
      const curve = algo && algo.namedCurve;
      return { name: 'ECDSA', hash: curve === 'P-384' ? 'SHA-384' : 'SHA-256' };
    }
    return { name: 'RSA-PSS', saltLength: 32 };
  }

  async function signData(text, signingKey, algo) {
    if (algo && algo.name === 'ML-DSA-65') {
      return signDataPQ(text, signingKey);
    }
    const sig = await crypto.subtle.sign(getSignAlg(algo), signingKey, new TextEncoder().encode(text));
    return b64Encode(new Uint8Array(sig));
  }

  async function verifyData(text, sigB64, pubKeyB64, algo) {
    try {
      if (algo && algo.name === 'ML-DSA-65') {
        return verifyDataPQ(text, sigB64, pubKeyB64);
      }
      algo = algo || { name: 'ECDSA', namedCurve: 'P-256' };
      const importAlg = algo.name === 'ECDSA'
        ? { name: 'ECDSA', namedCurve: algo.namedCurve || 'P-256' }
        : { name: 'RSA-PSS', hash: 'SHA-256' };
      const key = await crypto.subtle.importKey('spki', fromPem(pubKeyB64), importAlg, false, ['verify']);
      return crypto.subtle.verify(getSignAlg(algo), key,
        b64Decode(sigB64),
        new TextEncoder().encode(text));
    } catch { return false; }
  }

  async function generateDHKeypair() {
    return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  }

  async function deriveSharedDMKey(myDhPrivKey, theirDhPubKeyPem) {
    const theirPub = await crypto.subtle.importKey(
      'spki', fromPem(theirDhPubKeyPem), { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: theirPub },
      myDhPrivKey,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function persistDHPrivKey(dhPrivKey, fp) {
    const wrapKey = await derivePersistKey(fp);
    const iv      = crypto.getRandomValues(new Uint8Array(12));
    const raw     = await crypto.subtle.exportKey('pkcs8', dhPrivKey);
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, raw);
    const out     = new Uint8Array(12 + wrapped.byteLength);
    out.set(iv, 0); out.set(new Uint8Array(wrapped), 12);
    localStorage.setItem('cipher_dh_' + fp, b64Encode(out));
  }

  async function loadDHPrivKey(fp) {
    const stored = localStorage.getItem('cipher_dh_' + fp);
    if (!stored) return null;
    const buf     = b64Decode(stored);
    const wrapKey = await derivePersistKey(fp);
    try {
      const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0,12) }, wrapKey, buf.slice(12));
      return crypto.subtle.importKey('pkcs8', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    } catch { return null; }
  }

  async function derivePersistKey(fp) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(fp), 'PBKDF2', false, ['deriveKey']);
    const salt = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('cipher-dh-wrap:' + fp));
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function deriveDHPubFromPriv(dhPrivKey) {
    const jwk = await crypto.subtle.exportKey('jwk', dhPrivKey);
    delete jwk.d;
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  }

  async function aesEncrypt(plaintext, key) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv, 0); out.set(new Uint8Array(ct), 12);
    return b64Encode(out);
  }

  async function aesDecrypt(b64, key) {
    const buf   = b64Decode(b64);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0,12) }, key, buf.slice(12));
    return new TextDecoder().decode(plain);
  }

  const PQ_SK_PREFIX     = 'PQ-SK:';
  const PQ_KEM_SK_PREFIX = 'PQ-KEM-SK:';

  function pqAvailable() {
    return typeof noblePostQuantum !== 'undefined' ||
           (typeof ml_dsa65 !== 'undefined');
  }

  function getPQLib() {
    const dsa = window.ml_dsa65  || null;
    const kem = window.ml_kem768 || null;
    if (dsa && kem) return { ml_dsa65: dsa, ml_kem768: kem };

    let why = '';
    if (window._pqError) {
      why = ' Load error: ' + window._pqError + '.';
    } else if (!window._pqLoaded) {
      why = ' The file may be missing, misnamed, or blocked by the server.';
    }

    throw new Error(
      'Post-quantum library not available.' + why + ' ' +
      'Check the browser console for [PQ] messages. ' +
      'Make sure noble-post-quantum.js is in the same folder as index.html. ' +
      'Alternatively, select ECDSA P-256, P-384, or RSA-PSS.'
    );
  }

  function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  function bytesToB64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
  }

  async function generateMLDSAKeypair() {
    const { ml_dsa65 } = getPQLib();
    const seed = crypto.getRandomValues(new Uint8Array(32));
    return ml_dsa65.keygen(seed);
  }

  async function signDataPQ(text, secretKey) {
    const { ml_dsa65 } = getPQLib();
    const msg = new TextEncoder().encode(text);
    const sig = ml_dsa65.sign(secretKey, msg);
    return bytesToB64(sig);
  }

  async function verifyDataPQ(text, sigB64, publicKeyB64) {
    try {
      const { ml_dsa65 } = getPQLib();
      const msg = new TextEncoder().encode(text);
      const sig = b64ToBytes(sigB64);
      const pub = b64ToBytes(publicKeyB64);
      return ml_dsa65.verify(pub, msg, sig);
    } catch { return false; }
  }

  async function generateMLKEMKeypair() {
    const { ml_kem768 } = getPQLib();
    const seed = crypto.getRandomValues(new Uint8Array(64));
    return ml_kem768.keygen(seed);
  }

  async function kemEncapsulate(recipientPubKeyB64) {
    const { ml_kem768 } = getPQLib();
    const pub = b64ToBytes(recipientPubKeyB64);
    return ml_kem768.encapsulate(pub);
  }

  async function kemDecapsulate(ciphertextB64, secretKeyB64) {
    const { ml_kem768 } = getPQLib();
    const ct  = b64ToBytes(ciphertextB64);
    const sk  = b64ToBytes(secretKeyB64);
    return ml_kem768.decapsulate(ct, sk);
  }

  async function kemSharedSecretToAES(sharedSecret) {
    const base = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    const salt = new TextEncoder().encode('CIPHER//NET-KEM-AES-v1');
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array(0) },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function persistPQKEMKey(kemSecretKey, fp) {
    const wrapKey = await derivePersistKey(fp);
    const iv      = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, kemSecretKey);
    const out     = new Uint8Array(12 + wrapped.byteLength);
    out.set(iv, 0); out.set(new Uint8Array(wrapped), 12);
    localStorage.setItem('cipher_pqkem_' + fp, bytesToB64(out));
  }

  async function loadPQKEMKey(fp) {
    const stored = localStorage.getItem('cipher_pqkem_' + fp);
    if (!stored) return null;
    const buf     = b64ToBytes(stored);
    const wrapKey = await derivePersistKey(fp);
    try {
      const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0,12) }, wrapKey, buf.slice(12));
      return new Uint8Array(raw);
    } catch { return null; }
  }

  function encodePQSecretKey(secretKey) {
    return PQ_SK_PREFIX + bytesToB64(secretKey);
  }

  function decodePQSecretKey(str) {
    if (!str.startsWith(PQ_SK_PREFIX))
      throw new Error('Not a PQ secret key — expected PQ-SK: prefix.');
    return b64ToBytes(str.slice(PQ_SK_PREFIX.length));
  }

  function isPQKey(str) {
    return typeof str === 'string' && str.startsWith(PQ_SK_PREFIX);
  }

  const ENC_PREFIX  = 'CIPHER-ENC:v1:';
  const ENC_ITERS   = 300_000;

  async function encryptPrivateKey(pemStr, password) {
    const enc      = new TextEncoder();
    const salt     = crypto.getRandomValues(new Uint8Array(16));
    const iv       = crypto.getRandomValues(new Uint8Array(12));
    const baseKey  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const aesKey   = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ENC_ITERS, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const ct       = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(pemStr));
    const out      = new Uint8Array(16 + 12 + ct.byteLength);
    out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(ct), 28);
    return ENC_PREFIX + btoa(String.fromCharCode(...out));
  }

  async function decryptPrivateKey(encStr, password) {
    if (!encStr.startsWith(ENC_PREFIX))
      throw new Error('Not an encrypted key — paste your password-protected CIPHER-ENC export.');
    const enc     = new TextEncoder();
    const buf     = Uint8Array.from(atob(encStr.slice(ENC_PREFIX.length)), c => c.charCodeAt(0));
    const salt    = buf.slice(0, 16);
    const iv      = buf.slice(16, 28);
    const ct      = buf.slice(28);
    const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const aesKey  = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ENC_ITERS, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
      return new TextDecoder().decode(plain);
    } catch {
      throw new Error('Wrong password — decryption failed.');
    }
  }

  function isEncryptedKey(str) {
    return str.trim().startsWith(ENC_PREFIX);
  }

  async function deriveChannelKey(passphrase, channel) {
    const enc  = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    const salt = await crypto.subtle.digest('SHA-256', enc.encode('cipher-channel:' + channel));
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  window.CipherNet.Crypto = {
    b64Encode, b64Decode, toPem, fromPem,
    exportPrivPem, exportPubPem,
    generateECDSA, generateRSAPSS, importPrivateKey, derivePublicFromPrivate,
    fingerprint, getSignAlg, signData, verifyData,
    generateDHKeypair, deriveSharedDMKey, persistDHPrivKey, loadDHPrivKey,
    derivePersistKey, deriveDHPubFromPriv,
    aesEncrypt, aesDecrypt,
    PQ_SK_PREFIX, PQ_KEM_SK_PREFIX, pqAvailable, getPQLib,
    b64ToBytes, bytesToB64,
    generateMLDSAKeypair, signDataPQ, verifyDataPQ,
    generateMLKEMKeypair, kemEncapsulate, kemDecapsulate,
    kemSharedSecretToAES, persistPQKEMKey, loadPQKEMKey,
    encodePQSecretKey, decodePQSecretKey, isPQKey,
    ENC_PREFIX, ENC_ITERS, encryptPrivateKey, decryptPrivateKey, isEncryptedKey,
    deriveChannelKey,
  };
})();
