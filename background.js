import HeaderAnalyzer from './headerAnalyzer.js';
import ScannerManager from './scannerManager.js';

const scannerManager = new ScannerManager();
scannerManager.register('headers', new HeaderAnalyzer());

const tabSecurityStates = new Map();

chrome.webRequest.onHeadersReceived.addListener(
    async (details) => {
        try {
            if (details.type !== 'main_frame') return;

            const headers = {};
            if (details.responseHeaders) {
                details.responseHeaders.forEach(header => {
                    headers[header.name.toLowerCase()] = header.value;
                });
            }

            const scanResult = await scannerManager.scan('headers', headers);

            tabSecurityStates.set(details.tabId, {
                url: details.url,
                timestamp: Date.now(),
                scanResult: scanResult,
                headers: headers
            });

            console.log('putSecurityState:', details.tabId, scanResult);

            updateIcon(details.tabId, scanResult.riskLevel);

           

        } catch (error) {
            console.error('Background error:', error);
        }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders']
);
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // content.js 告诉我们它准备好了
    if (request.action === 'contentScriptReady' && sender.tab?.id != null) {
        const tabId = sender.tab.id;
        const state = tabSecurityStates.get(tabId);

        if (state) {
            console.log('[HeaderSense] content script ready, sending scanResult to tab:', tabId);
            chrome.tabs.sendMessage(tabId, {
                action: 'securityScanResult',
                result: state.scanResult
            }, () => {
                if (chrome.runtime.lastError) {
                    console.warn('Send to content.js failed:', chrome.runtime.lastError.message);
                }
            });
        } else {
            console.log('[HeaderSense] content script ready, but no scanResult for tab', tabId);
        }
    }

    // popup.js 请求当前标签页的 scan state
    if (request.action === 'getSecurityState') {
        const state = tabSecurityStates.get(request.tabId) || null;
        console.log('getSecurityState:', request.tabId, state);
        sendResponse(state);
        return true;
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        // console.log('Tab updated:', tabId, changeInfo);
        // tabSecurityStates.delete(tabId);
        // updateIcon(tabId, 'unknown');
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    tabSecurityStates.delete(tabId);
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getSecurityState') {
        const state = tabSecurityStates.get(request.tabId) || null;
        console.log('getSecurityState:', request.tabId, state);
        sendResponse(state);
        return true;
    }
});

function updateIcon(tabId, riskLevel) {
    const iconPaths = {
        high: {
            16: 'icons/icon16-red.png',
            48: 'icons/icon48-red.png',
            128: 'icons/icon128-red.png'
        },
        medium: {
            16: 'icons/icon16-orange.png',
            48: 'icons/icon48-orange.png',
            128: 'icons/icon128-orange.png'
        },
        low: {
            16: 'icons/icon16-green.png',
            48: 'icons/icon48-green.png',
            128: 'icons/icon128-green.png'
        },
        unknown: {
            16: 'icons/icon16.png',
            48: 'icons/icon48.png',
            128: 'icons/icon128.png'
        }
    };

    const path = iconPaths[riskLevel] || iconPaths.unknown;

    chrome.action.setIcon({ path });
    chrome.action.setBadgeText({
        text: riskLevel === 'high' ? '!' : ''
    });
    chrome.action.setBadgeBackgroundColor({
        color: riskLevel === 'high' ? '#FF0000' : '#555555'
    });
}