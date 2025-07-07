// simple_fast_background.js - 快速稳定版background脚本

import HeaderAnalyzer from './headerAnalyzer.js';
import ScannerManager from './scannerManager.js';

// 本地扫描器管理器
const scannerManager = new ScannerManager();
scannerManager.register('headers', new HeaderAnalyzer());

// 标签页安全状态存储
const tabSecurityStates = new Map();

// 防止重复扫描的节流器
const scanThrottler = new Map();

console.log('[HeaderSense] 快速版Background Script 已加载');

// 监听网页请求，获取响应头
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        // 只处理主框架请求
        if (details.type !== 'main_frame') return;
        
        // 节流：同一标签页2秒内只扫描一次
        const now = Date.now();
        const lastScan = scanThrottler.get(details.tabId);
        if (lastScan && (now - lastScan) < 2000) {
            console.log('[HeaderSense] 跳过重复扫描:', details.tabId);
            return;
        }
        
        scanThrottler.set(details.tabId, now);
        
        // 立即处理，不使用async/await避免阻塞
        processHeaders(details.tabId, details.url, details.responseHeaders);
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders']
);

/**
 * 快速处理响应头
 */
function processHeaders(tabId, url, responseHeaders) {
    try {
        // 转换响应头格式
        const headers = {};
        if (responseHeaders) {
            responseHeaders.forEach(header => {
                headers[header.name.toLowerCase()] = header.value;
            });
        }

        console.log('[HeaderSense] 处理请求:', url.substring(0, 50) + '...');

        // 立即执行本地扫描（同步）
        scannerManager.scan('headers', headers)
            .then(scanResult => {
                // 存储结果
                tabSecurityStates.set(tabId, {
                    url: url,
                    timestamp: Date.now(),
                    scanResult: scanResult,
                    headers: headers,
                    scanMode: 'local'
                });

                console.log('[HeaderSense] 扫描完成:', tabId, scanResult.riskLevel);

                // 更新图标
                updateIcon(tabId, scanResult.riskLevel);

                // 高风险时通知content script
                if (scanResult.riskLevel === 'high') {
                    notifyContentScript(tabId, scanResult);
                }
            })
            .catch(error => {
                console.error('[HeaderSense] 扫描失败:', error);
                
                // 设置错误状态
                tabSecurityStates.set(tabId, {
                    url: url,
                    timestamp: Date.now(),
                    scanResult: {
                        riskLevel: 'unknown',
                        score: 0,
                        issues: [],
                        summary: '扫描失败',
                        error: error.message
                    },
                    headers: headers
                });
                
                updateIcon(tabId, 'unknown');
            });

    } catch (error) {
        console.error('[HeaderSense] 处理响应头失败:', error);
    }
}

/**
 * 通知content script
 */
function notifyContentScript(tabId, scanResult) {
    chrome.tabs.sendMessage(tabId, {
        action: 'securityScanResult',
        result: scanResult
    }, () => {
        // 忽略错误，避免日志噪音
        if (chrome.runtime.lastError) {
            console.debug('[HeaderSense] Content script不可用');
        }
    });
}

/**
 * 更新扩展图标
 */
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

    // 使用Promise.catch避免错误影响性能
    chrome.action.setIcon({ 
        path: path,
        tabId: tabId 
    }).catch(() => {});
    
    chrome.action.setBadgeText({
        text: riskLevel === 'high' ? '!' : '',
        tabId: tabId
    }).catch(() => {});
    
    chrome.action.setBadgeBackgroundColor({
        color: riskLevel === 'high' ? '#FF0000' : '#555555',
        tabId: tabId
    }).catch(() => {});
}

// 监听popup消息
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    try {
        // content script准备就绪
        if (request.action === 'contentScriptReady' && sender.tab?.id != null) {
            const tabId = sender.tab.id;
            const state = tabSecurityStates.get(tabId);

            if (state && state.scanResult.riskLevel === 'high') {
                notifyContentScript(tabId, state.scanResult);
            }
            return;
        }

        // popup请求获取安全状态
        if (request.action === 'getSecurityState') {
            const state = tabSecurityStates.get(request.tabId);
            console.log('[HeaderSense] 返回状态:', request.tabId, state ? '有数据' : '无数据');
            sendResponse(state || null);
            return true;
        }

        // popup请求重新扫描
        if (request.action === 'rescan') {
            // 清除旧状态
            tabSecurityStates.delete(request.tabId);
            scanThrottler.delete(request.tabId);
            
            // 重新加载页面触发扫描
            chrome.tabs.reload(request.tabId, () => {
                if (chrome.runtime.lastError) {
                    sendResponse({ success: false, error: chrome.runtime.lastError.message });
                } else {
                    sendResponse({ success: true });
                }
            });
            return true;
        }

        // 获取扫描模式（简化版只支持本地模式）
        if (request.action === 'getScanMode') {
            sendResponse({ mode: 'local' });
            return true;
        }

        // 设置扫描模式（简化版忽略）
        if (request.action === 'setScanMode') {
            sendResponse({ success: true, mode: 'local' });
            return true;
        }

        // 检查后端状态（简化版总是返回不可用）
        if (request.action === 'checkBackendStatus') {
            sendResponse({ 
                isHealthy: false,
                backendUrl: 'N/A',
                currentMode: 'local',
                message: '简化版仅支持本地扫描'
            });
            return true;
        }

        // 详细扫描（简化版返回当前结果）
        if (request.action === 'startDetailedScan') {
            const state = tabSecurityStates.get(request.tabId);
            if (state) {
                sendResponse({ success: true, result: state.scanResult });
            } else {
                sendResponse({ success: false, error: '无扫描数据' });
            }
            return true;
        }

    } catch (error) {
        console.error('[HeaderSense] 消息处理错误:', error);
        sendResponse({ success: false, error: error.message });
    }
});

// 监听标签页更新
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        // 清理旧状态
        tabSecurityStates.delete(tabId);
        scanThrottler.delete(tabId);
        updateIcon(tabId, 'unknown');
    }
});

// 监听标签页关闭
chrome.tabs.onRemoved.addListener((tabId) => {
    tabSecurityStates.delete(tabId);
    scanThrottler.delete(tabId);
});

console.log('[HeaderSense] 快速版初始化完成');