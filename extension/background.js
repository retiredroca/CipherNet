// CIPHER//NET browser extension — MV3 service worker.
// Clicking the toolbar action opens the bundled app in a full tab.
'use strict';

chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: chrome.runtime.getURL('app/index.html') });
});