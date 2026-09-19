window.CipherNet = window.CipherNet || {};
(function() {
  'use strict';
  const $ = window.CipherNet.Util.$;
  const toast = window.CipherNet.Util.toast;

  const THEME_KEY = 'cipher_theme';

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    document.querySelectorAll('.theme-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.theme === theme);
    });
  }

  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY) || 'matrix';
    applyTheme(saved);

    const toggleBtn  = $('theme-toggle-btn');
    const switcher   = $('theme-switcher');
    if (!toggleBtn || !switcher) return;

    toggleBtn.addEventListener('click', e => {
      e.stopPropagation();
      switcher.classList.toggle('open');
    });

    document.addEventListener('click', e => {
      if (!switcher.contains(e.target) && e.target !== toggleBtn)
        switcher.classList.remove('open');
    });

    switcher.querySelectorAll('.theme-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        applyTheme(btn.dataset.theme);
        toast('Theme: ' + btn.textContent.trim());
      });
    });
  }

  document.addEventListener('DOMContentLoaded', initTheme);

  window.CipherNet.Theme = { applyTheme, initTheme };
})();
