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
