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
