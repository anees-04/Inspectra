// Background service worker
console.log('Security Scanner background script loaded');

const latestMainFrameHeadersByTabId = new Map();

function normalizeResponseHeaders(responseHeaders) {
  const headerMap = Object.create(null);
  for (const h of responseHeaders || []) {
    if (!h || !h.name) continue;
    const key = String(h.name).toLowerCase();
    const value = h.value == null ? '' : String(h.value);
    if (!headerMap[key]) headerMap[key] = [];
    headerMap[key].push(value);
  }
  return headerMap;
}

// Observe real response headers for the top-level document
try {
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (!details || typeof details.tabId !== 'number' || details.tabId < 0) return;

      latestMainFrameHeadersByTabId.set(details.tabId, {
        url: details.url,
        timeStamp: details.timeStamp,
        headers: normalizeResponseHeaders(details.responseHeaders)
      });
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
    ['responseHeaders', 'extraHeaders']
  );
} catch (e) {
  console.warn('webRequest header observation not available:', e);
}

chrome.runtime.onInstalled.addListener(() => {
  console.log('Security Scanner extension installed');
});

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request && request.action === 'getResponseHeaders') {
    const tabId = sender && sender.tab ? sender.tab.id : undefined;
    if (typeof tabId !== 'number') {
      sendResponse({ ok: false, error: 'No tab context available for response headers.' });
      return;
    }

    const snapshot = latestMainFrameHeadersByTabId.get(tabId) || null;
    sendResponse({ ok: true, snapshot });
    return true;
  }

  if (request.action === 'updateBadge') {
    chrome.action.setBadgeText({
      text: request.count.toString(),
      tabId: sender.tab.id
    });
    chrome.action.setBadgeBackgroundColor({
      color: request.severity === 'critical' ? '#e74c3c' : 
             request.severity === 'high' ? '#ff9800' : '#ffc107'
    });
  }
  return true;
});
