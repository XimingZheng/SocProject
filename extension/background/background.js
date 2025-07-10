// 改进的 background.js - 修复 Header 检测问题

import HeaderAnalyzer from './headerAnalyzer.js';
import ScannerManager from './scannerManager.js';

// 后端API配置
const BACKEND_URL = 'http://localhost:5000';
const API_ENDPOINTS = {
    SCAN: `${BACKEND_URL}/api/scan`,
    QUICK_SCAN: `${BACKEND_URL}/api/scan/quick`,
    STATUS: `${BACKEND_URL}/api/scan/status`,
    HEALTH: `${BACKEND_URL}/api/health`
};

// 扫描模式配置
const SCAN_MODES = {
    BACKEND: 'backend',
    HYBRID: 'hybrid'
};

let currentScanMode = SCAN_MODES.BACKEND;
const scannerManager = new ScannerManager();
scannerManager.register('headers', new HeaderAnalyzer());

// 标签页安全状态存储
const tabSecurityStates = new Map();
const backendTasks = new Map();

// 改进的响应头监听器
chrome.webRequest.onHeadersReceived.addListener(
    async (details) => {
        try {
            if (details.type !== 'main_frame') return;

            // 更严格的头部处理
            const headers = {};
            const rawHeaders = {};
            
            if (details.responseHeaders) {
                details.responseHeaders.forEach(header => {
                    const name = header.name.toLowerCase();
                    const value = header.value;
                    
                    // 存储小写键名的版本
                    headers[name] = value;
                    // 同时存储原始大小写版本用于调试
                    rawHeaders[header.name] = value;
                });
            }

            console.log('[HeaderSense] 检测到页面请求:', details.url);
            console.log('[HeaderSense] 响应头:', headers);

            // 立即执行基本扫描
            await performSecurityScan(details.tabId, details.url, headers, rawHeaders);

            // 延迟执行内容扫描以获取 meta 标签中的 CSP
            setTimeout(() => {
                performContentScan(details.tabId, details.url, headers);
            }, 2000);

        } catch (error) {
            console.error('[HeaderSense] Background处理错误:', error);
        }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders']
);

/**
 * 执行安全扫描
 */
async function performSecurityScan(tabId, url, headers, rawHeaders) {
    try {
        let scanResult;

        switch (currentScanMode) {
            case SCAN_MODES.BACKEND:
                scanResult = await performBackendScan(url, headers);
                break;
            
            case SCAN_MODES.HYBRID:
            default:
                scanResult = await performHybridScan(url, headers);
                break;
        }

        // 存储扫描结果
        tabSecurityStates.set(tabId, {
            url: url,
            timestamp: Date.now(),
            scanResult: scanResult,
            headers: headers,
            rawHeaders: rawHeaders, // 保存原始头部用于调试
            scanMode: currentScanMode
        });

        console.log('[HeaderSense] 扫描完成:', tabId, scanResult.riskLevel);
        updateIcon(tabId, scanResult.riskLevel);

        // 通知content script
        if (scanResult.riskLevel === 'high') {
            chrome.tabs.sendMessage(tabId, {
                action: 'securityScanResult',
                result: scanResult
            }, () => {
                if (chrome.runtime.lastError) {
                    // 忽略content script不存在的错误
                }
            });
        }

    } catch (error) {
        console.error('[HeaderSense] 扫描失败:', error);
        
        tabSecurityStates.set(tabId, {
            url: url,
            timestamp: Date.now(),
            scanResult: {
                riskLevel: 'unknown',
                score: 0,
                issues: [],
                summary: '扫描失败: ' + error.message,
                scanMode: currentScanMode,
                error: error.message
            },
            headers: headers
        });
        
        updateIcon(tabId, 'unknown');
    }
}

/**
 * 执行内容扫描 - 检查 HTML 中的 CSP meta 标签
 */
async function performContentScan(tabId, url, headers) {
    try {
        // 获取页面内容
        const results = await chrome.scripting.executeScript({
            target: { tabId: tabId },
            function: extractMetaCSP
        });

        if (results && results[0] && results[0].result) {
            const metaCSP = results[0].result;
            
            if (metaCSP) {
                console.log('[HeaderSense] 发现 meta CSP:', metaCSP);
                
                // 更新头部信息，添加从 meta 标签中提取的 CSP
                const updatedHeaders = { ...headers };
                if (!updatedHeaders['content-security-policy']) {
                    updatedHeaders['content-security-policy'] = metaCSP;
                    updatedHeaders['_meta_csp'] = true; // 标记来源
                }

                // 重新扫描
                await performSecurityScan(tabId, url, updatedHeaders, headers);
            }
        }
    } catch (error) {
        console.error('[HeaderSense] 内容扫描失败:', error);
    }
}

/**
 * 在页面中执行的函数 - 提取 meta 标签中的 CSP
 */
function extractMetaCSP() {
    const metaTags = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"], meta[http-equiv="content-security-policy"]');
    
    if (metaTags.length > 0) {
        return metaTags[0].getAttribute('content');
    }
    
    return null;
}

/**
 * 改进的本地扫描
 */
async function performLocalScan(headers) {
    // 添加调试日志
    console.log('[HeaderSense] 执行本地扫描，头部:', Object.keys(headers));
    
    const result = await scannerManager.scan('headers', headers);
    
    // 添加调试信息
    result.debug = {
        headersFound: Object.keys(headers),
        cspFound: !!headers['content-security-policy'],
        cspValue: headers['content-security-policy'] || null
    };
    
    return result;
}

/**
 * 增强的后端扫描
 */
async function performBackendScan(url, headers) {
    try {
        const isBackendHealthy = await checkBackendHealth();
        if (!isBackendHealthy) {
            console.warn('[HeaderSense] 后端不可用，回退到本地扫描');
            return await performLocalScan(headers);
        }

        const taskResponse = await fetch(API_ENDPOINTS.SCAN, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: url,
                headers: headers
            })
        });

        if (!taskResponse.ok) {
            throw new Error(`后端扫描请求失败: ${taskResponse.status}`);
        }

        const taskData = await taskResponse.json();
        const taskId = taskData.task_id;

        console.log('[HeaderSense] 后端扫描任务已启动:', taskId);
        return await pollTaskStatus(taskId);

    } catch (error) {
        console.error('[HeaderSense] 后端扫描失败，回退到本地扫描:', error);
        return await performLocalScan(headers);
    }
}

/**
 * 混合扫描模式
 */
async function performHybridScan(url, headers) {
    try {
        // 先执行快速本地扫描
        const localResult = await performLocalScan(headers);
        console.log('[HeaderSense] 本地扫描完成');

        // 同时启动后端详细扫描
        const backendPromise = performQuickBackendScan(url, headers);

        // 等待后端扫描或超时
        const backendResult = await Promise.race([
            backendPromise,
            new Promise((resolve) => setTimeout(() => resolve(null), 5000))
        ]);

        if (backendResult) {
            console.log('[HeaderSense] 后端扫描完成，合并结果');
            return mergeScanResults(localResult, backendResult);
        } else {
            console.log('[HeaderSense] 后端扫描超时，使用本地结果');
            return localResult;
        }

    } catch (error) {
        console.error('[HeaderSense] 混合扫描失败，使用本地结果:', error);
        return await performLocalScan(headers);
    }
}

/**
 * 快速后端扫描
 */
async function performQuickBackendScan(url, headers) {
    try {
        const response = await fetch(API_ENDPOINTS.QUICK_SCAN, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: url,
                headers: headers
            })
        });

        if (!response.ok) {
            throw new Error(`快速扫描失败: ${response.status}`);
        }

        const result = await response.json();
        
        return {
            riskLevel: result.risk_level,
            score: result.security_score,
            issues: result.issues || [],
            summary: result.summary,
            timestamp: Date.now(),
            scanMode: 'quick_backend'
        };

    } catch (error) {
        console.error('[HeaderSense] 快速后端扫描失败:', error);
        return null;
    }
}

/**
 * 合并扫描结果
 */
function mergeScanResults(localResult, backendResult) {
    const riskLevels = ['low', 'medium', 'high'];
    const localRiskIndex = riskLevels.indexOf(localResult.riskLevel);
    const backendRiskIndex = riskLevels.indexOf(backendResult.riskLevel);
    const finalRiskLevel = riskLevels[Math.max(localRiskIndex, backendRiskIndex)];

    const allIssues = [...(localResult.issues || [])];
    
    if (backendResult.issues) {
        backendResult.issues.forEach(backendIssue => {
            const exists = allIssues.some(localIssue => 
                localIssue.header === backendIssue.title || 
                localIssue.type === backendIssue.vulnerability_type
            );
            if (!exists) {
                allIssues.push({
                    type: backendIssue.vulnerability_type,
                    header: backendIssue.title,
                    description: backendIssue.description,
                    riskLevel: backendIssue.risk_level,
                    fixSuggestion: backendIssue.fix_suggestion,
                    source: 'backend'
                });
            }
        });
    }

    return {
        riskLevel: finalRiskLevel,
        score: Math.min(localResult.score, backendResult.score),
        issues: allIssues,
        summary: `本地发现 ${localResult.issues?.length || 0} 个问题，后端发现 ${backendResult.issues?.length || 0} 个问题`,
        timestamp: Date.now(),
        scanMode: 'hybrid',
        localResult: localResult,
        backendResult: backendResult,
        debug: {
            ...localResult.debug,
            backendCSP: backendResult.issues?.some(i => i.vulnerability_type?.includes('CSP'))
        }
    };
}

// 其他函数保持不变...
async function pollTaskStatus(taskId, maxAttempts = 30) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
            const response = await fetch(`${API_ENDPOINTS.STATUS}/${taskId}`);
            
            if (!response.ok) {
                throw new Error(`状态查询失败: ${response.status}`);
            }

            const statusData = await response.json();
            
            if (statusData.status === 'completed') {
                console.log('[HeaderSense] 后端扫描任务完成:', taskId);
                return convertBackendResult(statusData.result);
            } else if (statusData.status === 'failed') {
                throw new Error(`后端扫描失败: ${statusData.error}`);
            }

            await new Promise(resolve => setTimeout(resolve, 1000));

        } catch (error) {
            console.error('[HeaderSense] 轮询任务状态失败:', error);
            if (attempt === maxAttempts - 1) {
                throw error;
            }
        }
    }

    throw new Error('后端扫描任务超时');
}

function convertBackendResult(backendResult) {
    return {
        riskLevel: backendResult.overall_risk_level,
        score: backendResult.security_score,
        issues: backendResult.results.map(result => ({
            type: result.vulnerability_type,
            header: result.title,
            description: result.description,
            riskLevel: result.risk_level,
            explanation: result.description,
            fixSuggestion: result.fix_suggestion,
            evidence: result.evidence,
            timestamp: result.timestamp,
            source: 'backend'
        })),
        summary: backendResult.summary,
        timestamp: Date.now(),
        scanMode: 'backend',
        statistics: backendResult.statistics
    };
}

async function checkBackendHealth() {
    try {
        const response = await fetch(API_ENDPOINTS.HEALTH, {
            method: 'GET',
            timeout: 3000
        });
        return response.ok;
    } catch (error) {
        console.warn('[HeaderSense] 后端健康检查失败:', error);
        return false;
    }
}

function setScanMode(mode) {
    if (Object.values(SCAN_MODES).includes(mode)) {
        currentScanMode = mode;
        console.log('[HeaderSense] 扫描模式已切换为:', mode);
        chrome.storage.local.set({ scanMode: mode });
    }
}

chrome.storage.local.get(['scanMode'], (result) => {
    if (result.scanMode && Object.values(SCAN_MODES).includes(result.scanMode)) {
        currentScanMode = result.scanMode;
        console.log('[HeaderSense] 加载保存的扫描模式:', currentScanMode);
    }
});

// 监听来自popup的消息
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'contentScriptReady' && sender.tab?.id != null) {
        const tabId = sender.tab.id;
        const state = tabSecurityStates.get(tabId);

        if (state && state.scanResult.riskLevel === 'high') {
            chrome.tabs.sendMessage(tabId, {
                action: 'securityScanResult',
                result: state.scanResult
            }, () => {
                if (chrome.runtime.lastError) {
                    console.warn('[HeaderSense] 发送到content script失败:', chrome.runtime.lastError.message);
                }
            });
        }
    }

    if (request.action === 'getSecurityState') {
        const state = tabSecurityStates.get(request.tabId) || null;
        sendResponse(state);
        return true;
    }

    if (request.action === 'setScanMode') {
        setScanMode(request.mode);
        sendResponse({ success: true, mode: currentScanMode });
        return true;
    }

    if (request.action === 'getScanMode') {
        sendResponse({ mode: currentScanMode });
        return true;
    }

    if (request.action === 'rescan') {
        chrome.tabs.get(request.tabId, (tab) => {
            if (tab && tab.url) {
                chrome.tabs.reload(request.tabId);
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: '无法获取标签页信息' });
            }
        });
        return true;
    }

    if (request.action === 'startDetailedScan') {
        const state = tabSecurityStates.get(request.tabId);
        if (state) {
            performBackendScan(state.url, state.headers)
                .then(result => {
                    state.scanResult = result;
                    state.scanMode = 'backend_detailed';
                    tabSecurityStates.set(request.tabId, state);
                    
                    sendResponse({ success: true, result: result });
                })
                .catch(error => {
                    sendResponse({ success: false, error: error.message });
                });
        } else {
            sendResponse({ success: false, error: '未找到扫描状态' });
        }
        return true;
    }

    if (request.action === 'checkBackendStatus') {
        checkBackendHealth()
            .then(isHealthy => {
                sendResponse({ 
                    isHealthy: isHealthy,
                    backendUrl: BACKEND_URL,
                    currentMode: currentScanMode
                });
            })
            .catch(error => {
                sendResponse({ 
                    isHealthy: false, 
                    error: error.message,
                    backendUrl: BACKEND_URL,
                    currentMode: currentScanMode
                });
            });
        return true;
    }

    if (request.action === 'explainWithAI') {
        callAI(request.prompt)
            .then((text) => sendResponse({ success: true, text }))
            .catch((err) => sendResponse({ success: false, error: err.message }));
        return true;
    }
});

// 监听标签页更新
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        if (tabSecurityStates.has(tabId)) {
            tabSecurityStates.delete(tabId);
            updateIcon(tabId, 'unknown');
        }
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    tabSecurityStates.delete(tabId);
});

function updateIcon(tabId, riskLevel) {
    const iconPaths = {
        high: {
            16: '../icons/icon16-red.png',
            48: '../icons/icon48-red.png',
            128: '../icons/icon128-red.png'
        },
        medium: {
            16: '../icons/icon16-orange.png',
            48: '../icons/icon48-orange.png',
            128: '../icons/icon128-orange.png'
        },
        low: {
            16: '../icons/icon16-green.png',
            48: '../icons/icon48-green.png',
            128: '../icons/icon128-green.png'
        },
        unknown: {
            16: '../icons/shield-16.png',
            48: '../icons/shield-48.png',
            128: '../icons/shield-128.png'
        }
    };

    const path = iconPaths[riskLevel] || iconPaths.unknown;

    chrome.action.setIcon({ 
        path: path,
        tabId: tabId 
    });
    
    chrome.action.setBadgeText({
        text: riskLevel === 'high' ? '!' : '',
        tabId: tabId
    });
    
    chrome.action.setBadgeBackgroundColor({
        color: riskLevel === 'high' ? '#FF0000' : '#555555',
        tabId: tabId
    });
}

async function callAI(prompt) {
    const apiKey = 'AIzaSyDam_cmtdegN0Vo9o34Z-nsSFZ5sOWass4';

    const url = `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            contents: [
                {
                    parts: [
                        { text: prompt }
                    ]
                }
            ]
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Gemini 请求失败: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || '无结果';
}

console.log('[HeaderSense] Enhanced Background Script 已加载');
console.log('[HeaderSense] 后端URL:', BACKEND_URL);
console.log('[HeaderSense] 当前扫描模式:', currentScanMode);

checkBackendHealth().then(isHealthy => {
    console.log('[HeaderSense] 后端状态:', isHealthy ? '健康' : '不可用');
    if (!isHealthy) {
        console.warn('[HeaderSense] 后端不可用，自动切换到混合模式');
        setScanMode(SCAN_MODES.HYBRID);
    }
});