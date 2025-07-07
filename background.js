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

            updateIcon(details.tabId, scanResult.riskLevel);

            chrome.tabs.sendMessage(details.tabId, {
                action: 'securityScanResult',
                result: scanResult
            });

        } catch (error) {
            console.error('Background error:', error);
        }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders']
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        tabSecurityStates.delete(tabId);
        updateIcon(tabId, 'unknown');
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    tabSecurityStates.delete(tabId);
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getSecurityState') {
        const state = tabSecurityStates.get(request.tabId) || null;
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