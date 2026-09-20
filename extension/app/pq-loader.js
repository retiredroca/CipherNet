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
// ⚛ Post-quantum loader — ML-DSA-65 (sign) + ML-KEM-768 (KEM) for the
// lock screen. Tries esm.sh first (freshest), then falls back to the local
// bundled files for offline/OnionShare/extension contexts where network
// imports are unavailable or blocked by CSP.
'use strict';

async function tryLoad(url, label) {
  const m = await import(url);
  // esm.sh bundles sub-paths — export names vary, try all known patterns
  const dsa = m.ml_dsa65 || (m.default && m.default.ml_dsa65) || null;
  const kem = m.ml_kem768 || (m.default && m.default.ml_kem768) || null;
  if (!dsa || !kem) throw new Error('exports not found in ' + label + ': ' + Object.keys(m).join(', '));
  window.ml_dsa65  = dsa;
  window.ml_kem768 = kem;
  window._pqLoaded = true;
  console.log('[PQ] ⚛ Ready from', label, '| keys:', Object.keys(m).join(', '));
}

// Try loading both sub-modules from esm.sh simultaneously
try {
  const [dsaMod, kemMod] = await Promise.all([
    import('https://esm.sh/@noble/post-quantum@0.4.1/ml-dsa.js'),
    import('https://esm.sh/@noble/post-quantum@0.4.1/ml-kem.js'),
  ]);
  const dsa = dsaMod.ml_dsa65 || (dsaMod.default && dsaMod.default.ml_dsa65);
  const kem = kemMod.ml_kem768 || (kemMod.default && kemMod.default.ml_kem768);
  if (!dsa || !kem) throw new Error('exports missing. ml-dsa keys: ' + Object.keys(dsaMod).join(',') + ' ml-kem keys: ' + Object.keys(kemMod).join(','));
  window.ml_dsa65  = dsa;
  window.ml_kem768 = kem;
  window._pqLoaded = true;
  console.log('[PQ] ⚛ Loaded from esm.sh | ml_dsa65:', typeof dsa, '| ml_kem768:', typeof kem);
} catch (e) {
  console.warn('[PQ] esm.sh failed:', e.message, '— trying local file');
  // Local file fallback — use absolute path from current page location
  const base = location.href.substring(0, location.href.lastIndexOf('/') + 1);
  const localNames = ['noble-post-quantum.js', 'noble-pq.js'];
  let loaded = false;
  for (const name of localNames) {
    try {
      const m = await import(base + name);
      const dsa = m.ml_dsa65 || (m.default && m.default.ml_dsa65);
      const kem = m.ml_kem768 || (m.default && m.default.ml_kem768);
      if (dsa && kem) {
        window.ml_dsa65 = dsa; window.ml_kem768 = kem; window._pqLoaded = true;
        console.log('[PQ] ⚛ Loaded from local file:', name);
        loaded = true; break;
      }
    } catch (le) { console.warn('[PQ] local', name, 'failed:', le.message); }
  }
  if (!loaded) {
    window._pqError = 'esm.sh: ' + e.message;
    console.error('[PQ] PQ unavailable. Select ECDSA P-256 as algorithm.');
  }
}