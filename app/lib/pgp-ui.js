window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;
  const { state } = window.CipherNet.State;

  const pgpState = {
    privateKey: null,
    publicKey:  null,
  };

  function pgpAvailable() {
    if (typeof openpgp === 'undefined') {
      toast('openpgp.min.js not loaded \u2014 see GET_OPENPGP.md');
      return false;
    }
    return true;
  }

  function pgpShowPanel(name) {
    ['export','import','encrypt','decrypt'].forEach(p => {
      const el = $('pgp-panel-' + p);
      if (el) el.classList.toggle('hidden', p !== name);
    });
  }

  function pgpShowModal(panel, title) {
    $('pgp-modal-title').textContent = '// PGP \u2014 ' + title;
    pgpShowPanel(panel);
    $('pgp-modal').classList.remove('hidden');
  }

  function pgpCloseModal() {
    $('pgp-modal').classList.add('hidden');
  }

  function pgpErr(id, msg) {
    const el = $(id);
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  function pgpClearErr(id) {
    const el = $(id);
    if (el) { el.textContent = ''; el.classList.add('hidden'); }
  }

  function pgpDownload(content, filename) {
    const url = URL.createObjectURL(new Blob([content], { type: 'application/pgp-keys' }));
    const a   = Object.assign(document.createElement('a'), { href: url, download: filename });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function pgpExportKeypair() {
    if (!pgpAvailable() || !state.me) { toast('Sign in first'); return; }
    pgpClearErr('pgp-export-error');

    const btn = $('pgp-export-btn');
    btn.textContent = 'GENERATING...'; btn.disabled = true;

    try {
      const uid        = $('pgp-uid').value.trim() || state.me.handle + ' <' + state.me.handle + '@ciphernet>';
      const passphrase = $('pgp-export-pass').value || undefined;

      const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'rsa',
        rsaBits: 4096,
        userIDs: [{ name: uid }],
        passphrase,
        format: 'armored',
      });

      $('pgp-pub-out').value = publicKey;
      $('pgp-sec-out').value = privateKey;
      $('pgp-export-output').classList.remove('hidden');
      toast('PGP keypair generated');

      const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });
      pgpState.publicKey  = await openpgp.readKey({ armoredKey: publicKey });
      pgpState.privateKey = passphrase
        ? await openpgp.decryptKey({ privateKey: parsed, passphrase })
        : parsed;

    } catch (e) {
      pgpErr('pgp-export-error', 'Export failed: ' + e.message);
    }
    btn.textContent = 'GENERATE PGP KEYPAIR'; btn.disabled = false;
  }

  async function pgpImportKey() {
    if (!pgpAvailable()) return;
    pgpClearErr('pgp-import-error');

    const armoredKey = $('pgp-import-key').value.trim();
    const passphrase = $('pgp-import-pass').value || undefined;
    if (!armoredKey) { pgpErr('pgp-import-error', 'Paste your armored private key.'); return; }

    const btn = $('pgp-import-btn');
    btn.textContent = 'IMPORTING...'; btn.disabled = true;

    try {
      const privateKey = await openpgp.readPrivateKey({ armoredKey });
      const decrypted  = passphrase
        ? await openpgp.decryptKey({ privateKey, passphrase })
        : privateKey;

      pgpState.privateKey = decrypted;
      pgpState.publicKey  = decrypted.toPublic();

      const uid = decrypted.getUserIDs()[0] || 'unknown';
      const fp  = decrypted.getFingerprint().toUpperCase();

      toast('GPG key imported: ' + uid);
      pgpErr('pgp-import-error', '');
      const el = $('pgp-import-error');
      if (el) {
        el.textContent = '\u2713 Imported: ' + uid + '\n  fp: ' + fp;
        el.style.color = 'var(--green3)';
        el.classList.remove('hidden');
      }
    } catch (e) {
      pgpErr('pgp-import-error', 'Import failed: ' + e.message);
    }
    btn.textContent = 'IMPORT GPG KEY'; btn.disabled = false;
  }

  async function pgpEncryptMessage() {
    if (!pgpAvailable()) return;
    pgpClearErr('pgp-encrypt-error');

    if (!pgpState.privateKey) {
      pgpErr('pgp-encrypt-error', 'No PGP key loaded. Export a keypair or import a GPG key first.');
      return;
    }

    const recipientArmored = $('pgp-enc-pubkey').value.trim();
    const plaintext        = $('pgp-enc-plain').value;
    if (!recipientArmored) { pgpErr('pgp-encrypt-error', 'Paste the recipient\'s PGP public key.'); return; }
    if (!plaintext)        { pgpErr('pgp-encrypt-error', 'Enter a message to encrypt.'); return; }

    const btn = $('pgp-enc-btn');
    btn.textContent = 'ENCRYPTING...'; btn.disabled = true;

    try {
      const recipientKey = await openpgp.readKey({ armoredKey: recipientArmored });
      const encrypted    = await openpgp.encrypt({
        message:            await openpgp.createMessage({ text: plaintext }),
        encryptionKeys:     recipientKey,
        signingKeys:        pgpState.privateKey,
        format:             'armored',
      });
      $('pgp-enc-out').value = encrypted;
      $('pgp-enc-out-group').classList.remove('hidden');
      toast('Message encrypted & signed');
    } catch (e) {
      pgpErr('pgp-encrypt-error', 'Encryption failed: ' + e.message);
    }
    btn.textContent = 'ENCRYPT & SIGN'; btn.disabled = false;
  }

  async function pgpDecryptMessage() {
    if (!pgpAvailable()) return;
    pgpClearErr('pgp-decrypt-error');

    if (!pgpState.privateKey) {
      pgpErr('pgp-decrypt-error', 'No PGP key loaded. Export a keypair or import a GPG key first.');
      return;
    }

    const armoredMsg    = $('pgp-dec-cipher').value.trim();
    const senderArmored = $('pgp-dec-pubkey').value.trim();
    if (!armoredMsg) { pgpErr('pgp-decrypt-error', 'Paste the encrypted PGP message.'); return; }

    const btn = $('pgp-dec-btn');
    btn.textContent = 'DECRYPTING...'; btn.disabled = true;

    try {
      const message = await openpgp.readMessage({ armoredMessage: armoredMsg });

      const decryptOpts = {
        message,
        decryptionKeys: pgpState.privateKey,
        format: 'utf8',
      };

      if (senderArmored) {
        decryptOpts.verificationKeys = await openpgp.readKey({ armoredKey: senderArmored });
      }

      const { data, signatures } = await openpgp.decrypt(decryptOpts);
      $('pgp-dec-out').value = data;
      $('pgp-dec-out-group').classList.remove('hidden');

      const sigEl = $('pgp-dec-sig-status');
      if (sigEl) {
        if (!senderArmored) {
          sigEl.textContent = '\u26a0 No sender key provided \u2014 signature not verified';
          sigEl.className   = 'pgp-sig-status warn';
        } else {
          try {
            await signatures[0].verified;
            sigEl.textContent = '\u2713 SIGNATURE VALID';
            sigEl.className   = 'pgp-sig-status ok';
          } catch {
            sigEl.textContent = '\u2717 SIGNATURE INVALID';
            sigEl.className   = 'pgp-sig-status fail';
          }
        }
      }
      toast('Message decrypted');
    } catch (e) {
      pgpErr('pgp-decrypt-error', 'Decryption failed: ' + e.message);
    }
    btn.textContent = 'DECRYPT'; btn.disabled = false;
  }

  function initPGP() {
    $('btn-pgp-export').addEventListener('click', () => pgpShowModal('export', 'EXPORT KEYPAIR'));
    $('btn-pgp-import').addEventListener('click', () => pgpShowModal('import', 'IMPORT GPG KEY'));
    $('btn-pgp-encrypt').addEventListener('click', () => {
      if (!pgpState.privateKey) { toast('Load a PGP key first \u2014 export or import'); pgpShowModal('export', 'EXPORT KEYPAIR'); return; }
      pgpShowModal('encrypt', 'ENCRYPT MESSAGE');
    });
    $('btn-pgp-decrypt').addEventListener('click', () => {
      if (!pgpState.privateKey) { toast('Load a PGP key first \u2014 export or import'); pgpShowModal('import', 'IMPORT GPG KEY'); return; }
      pgpShowModal('decrypt', 'DECRYPT MESSAGE');
    });

    $('pgp-export-cancel').addEventListener('click', pgpCloseModal);
    $('pgp-import-cancel').addEventListener('click', pgpCloseModal);
    $('pgp-enc-cancel').addEventListener('click',    pgpCloseModal);
    $('pgp-dec-cancel').addEventListener('click',    pgpCloseModal);

    $('pgp-modal').addEventListener('click', e => {
      if (e.target === $('pgp-modal')) pgpCloseModal();
    });

    $('pgp-export-btn').addEventListener('click', pgpExportKeypair);
    $('pgp-import-btn').addEventListener('click', pgpImportKey);
    $('pgp-enc-btn').addEventListener('click',    pgpEncryptMessage);
    $('pgp-dec-btn').addEventListener('click',    pgpDecryptMessage);

    $('pgp-copy-pub').addEventListener('click', () => {
      navigator.clipboard.writeText($('pgp-pub-out').value).then(() => toast('Public key copied'));
    });
    $('pgp-copy-sec').addEventListener('click', () => {
      navigator.clipboard.writeText($('pgp-sec-out').value).then(() => toast('Secret key copied'));
    });
    $('pgp-copy-enc').addEventListener('click', () => {
      navigator.clipboard.writeText($('pgp-enc-out').value).then(() => toast('Encrypted message copied'));
    });
    $('pgp-dl-pub').addEventListener('click', () => pgpDownload($('pgp-pub-out').value, 'ciphernet-public.asc'));
    $('pgp-dl-sec').addEventListener('click', () => pgpDownload($('pgp-sec-out').value, 'ciphernet-secret.asc'));
  }

  document.addEventListener('DOMContentLoaded', initPGP);

  window.CipherNet.PGP = {
    pgpState, pgpAvailable, pgpShowModal, pgpCloseModal,
    pgpExportKeypair, pgpImportKey, pgpEncryptMessage, pgpDecryptMessage,
    initPGP,
  };
})();
