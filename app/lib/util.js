window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';

  function $(id) { return document.getElementById(id); }

  function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  let toastTimer;
  function toast(msg) {
    const el = $('toast');
    el.textContent = '// ' + msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 2800);
  }

  function scrollToBottom() { const m = $('messages'); m.scrollTop = m.scrollHeight; }

  function showLoginError(msg) { const el = $('login-error'); el.textContent = msg; el.classList.remove('hidden'); }
  function hideLoginError()    { $('login-error').classList.add('hidden'); }

  function showDMModalError(msg) { const el = $('dm-modal-error'); el.textContent = msg; el.classList.remove('hidden'); }
  function closeDMModal()        { $('dm-key-modal').classList.add('hidden'); state.pendingDmFp = null; }

  function downloadJSON(data, filename) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a   = Object.assign(document.createElement('a'), { href: url, download: filename });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function handleDragOver(e)  { e.preventDefault(); $('drop-zone').classList.add('drag-over'); }
  function handleDragLeave()  { $('drop-zone').classList.remove('drag-over'); }
  function handleDrop(e) {
    e.preventDefault(); $('drop-zone').classList.remove('drag-over');
    if (e.dataTransfer.files[0] && window.CipherNet.Identity) {
      window.CipherNet.Identity.readIdentityFile(e.dataTransfer.files[0]);
    }
  }

  function showStorageWarning() {
    if (sessionStorage.getItem('cipher_warn_dismissed')) return;
    $('storage-warning').classList.remove('hidden');
  }

  function dismissStorageWarning() {
    $('storage-warning').classList.add('hidden');
    sessionStorage.setItem('cipher_warn_dismissed', '1');
  }

  window.CipherNet.Util = {
    $, escHtml, toast, toastTimer,
    scrollToBottom,
    showLoginError, hideLoginError,
    showDMModalError, closeDMModal,
    downloadJSON,
    handleDragOver, handleDragLeave, handleDrop,
    showStorageWarning, dismissStorageWarning,
  };
})();
