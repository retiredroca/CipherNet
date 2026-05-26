window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';

  (function initScreenProtection() {

    document.addEventListener('contextmenu', e => {
      e.preventDefault();
      return false;
    });

    document.addEventListener('keydown', e => {
      const ctrl = e.ctrlKey || e.metaKey;

      if (e.key === 'PrintScreen' || e.key === 'Snapshot') {
        e.preventDefault();
        showScreenshotWarning();
        return false;
      }

      if (ctrl && (e.key === 's' || e.key === 'S' ||
                   e.key === 'u' || e.key === 'U' ||
                   e.key === 'p' || e.key === 'P')) {
        e.preventDefault();
        return false;
      }

      if (e.key === 'F12') {
        e.preventDefault();
        return false;
      }
    });

    const blank = document.getElementById('screen-blank');

    function hideContent() {
      if (blank) blank.classList.add('active');
    }
    function showContent() {
      if (blank) blank.classList.remove('active');
    }

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) hideContent();
      else showContent();
    });

    window.addEventListener('blur', hideContent);
    window.addEventListener('focus', showContent);

    let warnTimer;
    function showScreenshotWarning() {
      const el = document.getElementById('screenshot-warn');
      if (!el) return;
      el.classList.add('show');
      clearTimeout(warnTimer);
      warnTimer = setTimeout(() => el.classList.remove('show'), 3000);
    }

    document.addEventListener('copy', e => {
      const sel = window.getSelection && window.getSelection();
      if (!sel || sel.toString().length === 0) {
        showScreenshotWarning();
      }
    });

  })();

  window.CipherNet.Deterrents = {};
})();
