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

  const state = {
    me: null,
    view: 'channel',
    channel: 'general',
    dmPeer: null,
    channelKeys: {},
    dmKeys: {},
    dmKemCiphertexts: null,
    pendingDmFp: null,
    generatedPrivPem:    null,
    generatedPubPem:     null,
    generatedCryptoKeys: null,
    generatedDHKeys:     null,
    generatedDHPubPem:   null,
    generatedAlgo:       null,
  };

  function getStoredUsers() {
    try { return JSON.parse(localStorage.getItem('cipher_users') || '{}'); } catch { return {}; }
  }

  window.CipherNet.State = { state, getStoredUsers };
})();
