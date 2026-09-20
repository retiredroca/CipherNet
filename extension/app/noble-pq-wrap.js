// CIPHER//NET — noble-post-quantum CSP bridge
// Place this file AND ml-dsa.js AND ml-kem.js next to index.html.
// This script loads the ES modules via a blob URL trick that bypasses
// the classic-script-can't-use-export limitation under CSP default-src 'self'.
//
// HOW TO GET ml-dsa.js and ml-kem.js:
//   npm install @noble/post-quantum@0.4.1
//   cp node_modules/@noble/post-quantum/ml-dsa.js ./ml-dsa.js
//   cp node_modules/@noble/post-quantum/ml-kem.js ./ml-kem.js
//   cp noble-pq-wrap.js next to index.html
//
// The files will be fetched via XHR (same-origin, CSP safe) then
// evaluated as modules via blob URLs.

(function() {
  'use strict';

  function fetchAndEval(filename) {
    return new Promise(function(resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', filename, true);
      xhr.onload = function() {
        if (xhr.status >= 200 && xhr.status < 400) {
          // Wrap in a blob URL so the browser treats it as a module
          var blob = new Blob([xhr.responseText], { type: 'application/javascript' });
          var url  = URL.createObjectURL(blob);
          var s    = document.createElement('script');
          s.type   = 'module';
          s.textContent = [
            'import * as mod from "' + url + '";',
            'window.__pqMod_' + filename.replace(/[^a-z]/gi,'_') + ' = mod;',
            'URL.revokeObjectURL("' + url + '");',
          ].join('\n');
          s.onload  = function() { resolve(window['__pqMod_' + filename.replace(/[^a-z]/gi,'_')]); };
          s.onerror = function(e) { reject(e); };
          document.head.appendChild(s);
        } else {
          reject(new Error(filename + ' returned ' + xhr.status));
        }
      };
      xhr.onerror = function() { reject(new Error('XHR failed for ' + filename)); };
      xhr.send();
    });
  }

  Promise.all([
    fetchAndEval('ml-dsa.js'),
    fetchAndEval('ml-kem.js'),
  ]).then(function(mods) {
    var dsaMod = mods[0], kemMod = mods[1];
    var dsa = dsaMod && (dsaMod.ml_dsa65 || dsaMod.default && dsaMod.default.ml_dsa65);
    var kem = kemMod && (kemMod.ml_kem768 || kemMod.default && kemMod.default.ml_kem768);
    if (dsa && kem) {
      window.ml_dsa65  = dsa;
      window.ml_kem768 = kem;
      window._pqLoaded = true;
      console.log('[PQ] ⚛ Ready via noble-pq-wrap.js');
    } else {
      console.warn('[PQ] ml-dsa.js/ml-kem.js loaded but ml_dsa65/ml_kem768 not found in exports.',
        'ml-dsa exports:', Object.keys(dsaMod || {}),
        'ml-kem exports:', Object.keys(kemMod || {}));
    }
  }).catch(function(e) {
    console.warn('[PQ] noble-pq-wrap.js failed:', e.message);
  });
})();
