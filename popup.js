// enhanced_popup.js - 支持后端通信的增强版popup脚本

let currentMode = 'user';
let scanResults = null;
let currentTab = null;
let backendStatus = null;
let currentScanMode = 'hybrid';

// 扫描模式配置
const SCAN_MODES = {
    LOCAL: 'local',      // 本地扫描
    BACKEND: 'backend',  // 后端扫描
    HYBRID: 'hybrid'     // 混合模式
};

const SCAN_MODE_LABELS = {
    'local': '🔧 本地扫描',
    'backend': '☁️ 后端扫描',
    'hybrid': '⚡ 智能模式'
};

// 初始化
document.addEventListener('DOMContentLoaded', function() {
    initializePopup();
    setupEventListeners();
});

// 初始化弹窗
async function initializePopup() {
    try {
        // 获取当前活动标签页
        const tabs = await chrome.tabs.query({active: true, currentWindow: true});
        currentTab = tabs[0];

        // 显示当前URL
        document.getElementById('currentUrl').textContent = currentTab.url;

        // 检查后端状态
        await checkBackendStatus();

        // 获取当前扫描模式
        await getCurrentScanMode();

        // 开始获取扫描结果
        await loadScanResults();
    } catch (error) {
        showError('初始化失败: ' + error.message);
    }
}

// 设置事件监听器
function setupEventListeners() {
    // 模式切换
    document.getElementById('userModeBtn').addEventListener('click', () => switchMode('user'));
    document.getElementById('developerModeBtn').addEventListener('click', () => switchMode('developer'));

    // 用户模式按钮
    document.getElementById('explainBtn').addEventListener('click', toggleExplanation);
    document.getElementById('refreshBtn').addEventListener('click', performRescan);

    // 开发者模式按钮
    document.getElementById('devRefreshBtn').addEventListener('click', performRescan);
    document.getElementById('exportBtn').addEventListener('click', exportReport);

    // 扫描模式切换按钮
    document.getElementById('scanModeBtn').addEventListener('click', showScanModeSelector);
    document.getElementById('detailedScanBtn').addEventListener('click', startDetailedScan);
    document.getElementById('backendStatusBtn').addEventListener('click', showBackendStatus);

    // 折叠区域切换
    document.getElementById('toggleOverview').addEventListener('click', () => toggleSection('overview'));
    document.getElementById('toggleIssues').addEventListener('click', () => toggleSection('issues'));
    document.getElementById('toggleHeaders').addEventListener('click', () => toggleSection('headers'));
}

// 检查后端状态
async function checkBackendStatus() {
    try {
        const response = await chrome.runtime.sendMessage({ action: 'checkBackendStatus' });
        backendStatus = response;
        updateBackendStatusUI();
    } catch (error) {
        console.error('检查后端状态失败:', error);
        backendStatus = { isHealthy: false, error: error.message };
        updateBackendStatusUI();
    }
}

// 获取当前扫描模式
async function getCurrentScanMode() {
    try {
        const response = await chrome.runtime.sendMessage({ action: 'getScanMode' });
        currentScanMode = response.mode;
        updateScanModeUI();
    } catch (error) {
        console.error('获取扫描模式失败:', error);
    }
}

// 更新后端状态UI
function updateBackendStatusUI() {
    const statusBtn = document.getElementById('backendStatusBtn');
    if (!statusBtn) return;

    if (backendStatus.isHealthy) {
        statusBtn.innerHTML = '🟢 后端在线';
        statusBtn.style.color = '#4CAF50';
        statusBtn.title = `后端服务正常 - ${backendStatus.backendUrl}`;
    } else {
        statusBtn.innerHTML = '🔴 后端离线';
        statusBtn.style.color = '#f44336';
        statusBtn.title = `后端服务不可用 - ${backendStatus.backendUrl || 'Unknown'}`;
    }
}

// 更新扫描模式UI
function updateScanModeUI() {
    const scanModeBtn = document.getElementById('scanModeBtn');
    if (!scanModeBtn) return;

    const modeLabel = SCAN_MODE_LABELS[currentScanMode] || currentScanMode;
    scanModeBtn.innerHTML = modeLabel;
    
    // 根据模式设置样式
    scanModeBtn.className = 'btn btn-secondary scan-mode-btn';
    
    if (currentScanMode === 'backend' && !backendStatus?.isHealthy) {
        scanModeBtn.style.backgroundColor = '#ffeb3b';
        scanModeBtn.style.color = '#333';
        scanModeBtn.title = '后端模式但服务不可用，将自动回退到本地扫描';
    }
}

// 显示扫描模式选择器
function showScanModeSelector() {
    const modal = createModal('选择扫描模式', createScanModeContent());
    document.body.appendChild(modal);
}

// 创建扫描模式选择内容
function createScanModeContent() {
    const content = document.createElement('div');
    content.innerHTML = `
        <div class="scan-mode-options">
            <div class="mode-option ${currentScanMode === 'local' ? 'selected' : ''}" data-mode="local">
                <div class="mode-icon">🔧</div>
                <div class="mode-info">
                    <h4>本地扫描</h4>
                    <p>仅检查HTTP响应头，速度快，无需网络</p>
                    <div class="mode-pros">✓ 速度快 ✓ 隐私保护</div>
                </div>
            </div>
            
            <div class="mode-option ${currentScanMode === 'backend' ? 'selected' : ''}" data-mode="backend" ${!backendStatus?.isHealthy ? 'disabled' : ''}>
                <div class="mode-icon">☁️</div>
                <div class="mode-info">
                    <h4>后端扫描</h4>
                    <p>全面安全检测，包括XSS、SQL注入等</p>
                    <div class="mode-pros">✓ 功能完整 ✓ 检测深度高</div>
                    ${!backendStatus?.isHealthy ? '<div class="mode-warning">⚠️ 后端服务不可用</div>' : ''}
                </div>
            </div>
            
            <div class="mode-option ${currentScanMode === 'hybrid' ? 'selected' : ''}" data-mode="hybrid">
                <div class="mode-icon">⚡</div>
                <div class="mode-info">
                    <h4>智能模式 (推荐)</h4>
                    <p>快速本地扫描 + 详细后端分析</p>
                    <div class="mode-pros">✓ 兼顾速度与全面性 ✓ 自动回退</div>
                </div>
            </div>
        </div>
        
        <div class="mode-actions">
            <button class="btn btn-primary" id="confirmModeBtn">确认</button>
            <button class="btn btn-secondary" id="cancelModeBtn">取消</button>
        </div>
    `;

    // 添加事件监听
    content.addEventListener('click', (e) => {
        const modeOption = e.target.closest('.mode-option');
        if (modeOption && !modeOption.hasAttribute('disabled')) {
            // 清除其他选中状态
            content.querySelectorAll('.mode-option').forEach(opt => opt.classList.remove('selected'));
            // 设置当前选中
            modeOption.classList.add('selected');
        }
    });

    content.getElementById = function(id) {
        return this.querySelector('#' + id);
    };

    setTimeout(() => {
        const confirmBtn = content.querySelector('#confirmModeBtn');
        const cancelBtn = content.querySelector('#cancelModeBtn');

        confirmBtn.addEventListener('click', async () => {
            const selectedMode = content.querySelector('.mode-option.selected')?.dataset.mode;
            if (selectedMode && selectedMode !== currentScanMode) {
                await setScanMode(selectedMode);
            }
            document.querySelector('.modal-overlay').remove();
        });

        cancelBtn.addEventListener('click', () => {
            document.querySelector('.modal-overlay').remove();
        });
    }, 0);

    return content;
}

// 设置扫描模式
async function setScanMode(mode) {
    try {
        const response = await chrome.runtime.sendMessage({ 
            action: 'setScanMode', 
            mode: mode 
        });
        
        if (response.success) {
            currentScanMode = response.mode;
            updateScanModeUI();
            showToast(`扫描模式已切换为: ${SCAN_MODE_LABELS[mode]}`);
            
            // 重新扫描以应用新模式
            await performRescan();
        }
    } catch (error) {
        showToast('切换扫描模式失败: ' + error.message, 'error');
    }
}

// 显示后端状态详情
function showBackendStatus() {
    const content = document.createElement('div');
    content.innerHTML = `
        <div class="backend-status-details">
            <div class="status-item">
                <span class="status-label">后端地址:</span>
                <span class="status-value">${backendStatus.backendUrl || 'Unknown'}</span>
            </div>
            <div class="status-item">
                <span class="status-label">连接状态:</span>
                <span class="status-value ${backendStatus.isHealthy ? 'status-healthy' : 'status-error'}">
                    ${backendStatus.isHealthy ? '🟢 正常' : '🔴 异常'}
                </span>
            </div>
            <div class="status-item">
                <span class="status-label">当前模式:</span>
                <span class="status-value">${SCAN_MODE_LABELS[currentScanMode]}</span>
            </div>
            ${backendStatus.error ? `
                <div class="status-item">
                    <span class="status-label">错误信息:</span>
                    <span class="status-value status-error">${backendStatus.error}</span>
                </div>
            ` : ''}
        </div>
        
        <div class="backend-actions">
            <button class="btn btn-primary" id="recheckBackendBtn">重新检查</button>
            <button class="btn btn-secondary" id="closeStatusBtn">关闭</button>
        </div>
    `;

    const modal = createModal('后端服务状态', content);
    document.body.appendChild(modal);

    // 添加事件监听
    setTimeout(() => {
        document.getElementById('recheckBackendBtn').addEventListener('click', async () => {
            showToast('正在检查后端状态...');
            await checkBackendStatus();
            document.querySelector('.modal-overlay').remove();
            showBackendStatus(); // 重新显示更新后的状态
        });

        document.getElementById('closeStatusBtn').addEventListener('click', () => {
            document.querySelector('.modal-overlay').remove();
        });
    }, 0);
}

// 启动详细扫描
async function startDetailedScan() {
    try {
        showLoading();
        showToast('正在启动详细安全扫描...');

        const response = await chrome.runtime.sendMessage({ 
            action: 'startDetailedScan', 
            tabId: currentTab.id 
        });

        if (response.success) {
            scanResults = response.result;
            updateUserInterface(scanResults);
            showToast('详细扫描完成');
        } else {
            throw new Error(response.error || '详细扫描失败');
        }

        hideLoading();
    } catch (error) {
        hideLoading();
        showToast('详细扫描失败: ' + error.message, 'error');
    }
}

// 加载扫描结果
async function loadScanResults() {
    showLoading();

    try {
        const results = await getScanResultsFromBackground();

        if (results) {
            scanResults = results;
            updateUserInterface(results);
        } else {
            showError('无法获取扫描结果，正在重新扫描...');
            await performRescan();
        }

        hideLoading();
    } catch (error) {
        hideLoading();
        showError('获取扫描结果失败: ' + error.message);
    }
}

// 从后台获取扫描结果
async function getScanResultsFromBackground() {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(
            { action: 'getSecurityState', tabId: currentTab.id },
            (response) => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                } else if (response && response.scanResult) {
                    resolve({
                        ...response.scanResult,
                        headers: response.headers || {},
                        scanMode: response.scanMode || 'unknown'
                    });
                } else {
                    resolve(null);
                }
            }
        );
    });
}

// 执行重新扫描
async function performRescan() {
    try {
        showLoading();
        showToast('正在重新扫描...');

        const response = await chrome.runtime.sendMessage({ 
            action: 'rescan', 
            tabId: currentTab.id 
        });

        if (response.success) {
            // 等待扫描完成
            await new Promise(resolve => setTimeout(resolve, 2000));
            await loadScanResults();
            showToast('重新扫描完成');
        } else {
            throw new Error(response.error || '重新扫描失败');
        }
    } catch (error) {
        hideLoading();
        showToast('重新扫描失败: ' + error.message, 'error');
    }
}

// 切换模式
function switchMode(mode) {
    currentMode = mode;

    // 更新按钮状态
    document.querySelectorAll('.mode-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(mode + 'ModeBtn').classList.add('active');

    // 切换界面
    if (mode === 'user') {
        document.getElementById('userMode').style.display = 'block';
        document.getElementById('developerMode').style.display = 'none';
    } else {
        document.getElementById('userMode').style.display = 'none';
        document.getElementById('developerMode').style.display = 'block';
    }

    // 如果已有扫描结果，更新界面
    if (scanResults) {
        updateUserInterface(scanResults);
    }
}

// 更新用户界面
function updateUserInterface(results) {
    // 更新用户模式界面
    updateUserMode(results);

    // 更新开发者模式界面
    updateDeveloperMode(results);

    // 更新扫描信息显示
    updateScanInfo(results);
}

// 更新扫描信息
function updateScanInfo(results) {
    // 在URL信息下方添加扫描信息
    let scanInfo = document.getElementById('scanInfo');
    if (!scanInfo) {
        scanInfo = document.createElement('div');
        scanInfo.id = 'scanInfo';
        scanInfo.className = 'scan-info';
        
        const urlInfo = document.querySelector('.url-info');
        urlInfo.parentNode.insertBefore(scanInfo, urlInfo.nextSibling);
    }

    const scanModeText = SCAN_MODE_LABELS[results.scanMode] || results.scanMode;
    const scanTime = results.timestamp ? new Date(results.timestamp).toLocaleTimeString() : '未知';

    scanInfo.innerHTML = `
        <div class="scan-info-item">
            <span class="scan-label">扫描模式:</span>
            <span class="scan-value">${scanModeText}</span>
        </div>
        <div class="scan-info-item">
            <span class="scan-label">扫描时间:</span>
            <span class="scan-value">${scanTime}</span>
        </div>
        ${results.error ? `
            <div class="scan-info-item scan-error">
                <span class="scan-label">⚠️ 扫描警告:</span>
                <span class="scan-value">${results.error}</span>
            </div>
        ` : ''}
    `;
}

// 更新用户模式界面
function updateUserMode(results) {
    const badge = document.getElementById('securityBadge');
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreNumber = document.getElementById('scoreNumber');
    const scoreDescription = document.getElementById('scoreDescription');

    // 更新安全徽章
    badge.className = `security-badge ${results.riskLevel}`;

    let badgeText = '';
    let badgeIcon = '';

    if (results.riskLevel === 'high') {
        badgeText = '存在安全风险';
        badgeIcon = '⚠️';
    } else if (results.riskLevel === 'medium') {
        badgeText = '部分配置缺失';
        badgeIcon = '⚠️';
    } else if (results.riskLevel === 'low') {
        badgeText = '轻微问题';
        badgeIcon = '💡';
    } else {
        badgeText = '安全配置良好';
        badgeIcon = '✅';
    }

    badge.innerHTML = `<span class="icon">${badgeIcon}</span><span>${badgeText}</span>`;

    // 更新评分
    scoreCircle.className = `score-circle ${results.riskLevel}`;
    scoreNumber.textContent = results.score || 0;
    scoreDescription.textContent = `安全评分: ${results.score || 0}/100`;

    // 更新统计信息
    const highCount = results.issues ? results.issues.filter(issue => issue.riskLevel === 'high').length : 0;
    const mediumCount = results.issues ? results.issues.filter(issue => issue.riskLevel === 'medium').length : 0;
    const lowCount = results.issues ? results.issues.filter(issue => issue.riskLevel === 'low').length : 0;

    document.getElementById('highIssues').textContent = highCount;
    document.getElementById('mediumIssues').textContent = mediumCount;
    document.getElementById('lowIssues').textContent = lowCount;

    // 根据扫描模式显示额外按钮
    updateModeSpecificButtons(results);
}

// 更新模式特定的按钮
function updateModeSpecificButtons(results) {
    let actionButtons = document.getElementById('actionButtons');
    if (!actionButtons) {
        actionButtons = document.createElement('div');
        actionButtons.id = 'actionButtons';
        actionButtons.className = 'action-buttons';
        
        const buttonsContainer = document.querySelector('.buttons');
        buttonsContainer.parentNode.insertBefore(actionButtons, buttonsContainer.nextSibling);
    }

    let buttonsHTML = '';

    // 扫描模式按钮
    buttonsHTML += `
        <button class="btn btn-secondary" id="scanModeBtn">
            ${SCAN_MODE_LABELS[currentScanMode]}
        </button>
    `;

    // 后端状态按钮
    buttonsHTML += `
        <button class="btn btn-secondary" id="backendStatusBtn">
            ${backendStatus?.isHealthy ? '🟢 后端在线' : '🔴 后端离线'}
        </button>
    `;

    // 详细扫描按钮（当前为本地或快速扫描时）
    if (results.scanMode !== 'backend' && backendStatus?.isHealthy) {
        buttonsHTML += `
            <button class="btn btn-primary" id="detailedScanBtn">
                🔍 详细扫描
            </button>
        `;
    }

    actionButtons.innerHTML = buttonsHTML;

    // 重新绑定事件监听器
    setTimeout(() => {
        const scanModeBtn = document.getElementById('scanModeBtn');
        const backendStatusBtn = document.getElementById('backendStatusBtn');
        const detailedScanBtn = document.getElementById('detailedScanBtn');

        if (scanModeBtn) {
            scanModeBtn.addEventListener('click', showScanModeSelector);
        }

        if (backendStatusBtn) {
            backendStatusBtn.addEventListener('click', showBackendStatus);
        }

        if (detailedScanBtn) {
            detailedScanBtn.addEventListener('click', startDetailedScan);
        }
    }, 0);
}

// 更新开发者模式界面
function updateDeveloperMode(results) {
    // 更新统计信息
    const highCount = results.issues ? results.issues.filter(issue => issue.riskLevel === 'high').length : 0;
    const mediumCount = results.issues ? results.issues.filter(issue => issue.riskLevel === 'medium').length : 0;
    const lowCount = results.issues ? results.issues.filter(issue => issue.riskLevel === 'low').length : 0;

    document.getElementById('dev-high').textContent = highCount;
    document.getElementById('dev-medium').textContent = mediumCount;
    document.getElementById('dev-low').textContent = lowCount;

    // 更新问题列表
    const issuesList = document.getElementById('issuesList');
    issuesList.innerHTML = '';

    if (!results.issues || results.issues.length === 0) {
        issuesList.innerHTML = '<div class="empty-state"><div class="icon">🎉</div><div>未发现安全问题</div></div>';
    } else {
        results.issues.forEach((issue, index) => {
            const issueElement = document.createElement('div');
            issueElement.className = `issue-item ${issue.riskLevel}`;
            
            // 处理不同来源的问题格式
            const title = issue.header || issue.title || `问题 ${index + 1}`;
            const description = issue.description || '无描述';
            const fixSuggestion = issue.fixSuggestion || issue.fix_suggestion || '暂无修复建议';
            const evidence = issue.evidence || '';
            const source = issue.source || 'local';

            issueElement.innerHTML = `
                <div class="issue-header">
                    <div class="issue-title">${title}</div>
                    <div class="issue-source">${source === 'backend' ? '☁️ 后端' : '🔧 本地'}</div>
                </div>
                <div class="issue-description">${description}</div>
                ${evidence ? `<div class="issue-evidence"><strong>证据:</strong> ${evidence}</div>` : ''}
                <div class="issue-fix"><strong>修复建议:</strong> ${fixSuggestion}</div>
            `;
            issuesList.appendChild(issueElement);
        });
    }

    // 更新响应头列表
    const headersList = document.getElementById('headersList');
    headersList.innerHTML = '';

    if (results.headers && Object.keys(results.headers).length > 0) {
        Object.entries(results.headers).forEach(([name, value]) => {
            const headerElement = document.createElement('div');
            headerElement.className = 'header-item';
            headerElement.innerHTML = `
                <div class="header-name">${name}:</div>
                <div class="header-value">${value}</div>
            `;
            headersList.appendChild(headerElement);
        });
    } else {
        headersList.innerHTML = '<div class="empty-state">无响应头数据</div>';
    }
}

// 显示加载状态
function showLoading() {
    document.getElementById('loadingState').style.display = 'block';
    document.getElementById('errorState').style.display = 'none';
    document.getElementById('userMode').style.display = 'none';
    document.getElementById('developerMode').style.display = 'none';
}

// 隐藏加载状态
function hideLoading() {
    document.getElementById('loadingState').style.display = 'none';

    if (currentMode === 'user') {
        document.getElementById('userMode').style.display = 'block';
    } else {
        document.getElementById('developerMode').style.display = 'block';
    }
}

// 显示错误状态
function showError(message) {
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('userMode').style.display = 'none';
    document.getElementById('developerMode').style.display = 'none';
    document.getElementById('errorState').style.display = 'block';
    document.getElementById('errorState').innerHTML = `
        <div class="icon">⚠️</div>
        <div>检测失败</div>
        <div style="font-size: 12px; margin-top: 8px;">${message}</div>
    `;
}

// 切换解释内容
function toggleExplanation() {
    const content = document.getElementById('explanationContent');
    const btn = document.getElementById('explainBtn');

    if (content.style.display === 'none' || !content.style.display) {
        content.style.display = 'block';
        btn.innerHTML = '<span>🔼</span> 收起解释';
    } else {
        content.style.display = 'none';
        btn.innerHTML = '<span>💡</span> 一键解释';
    }
}

// 切换折叠区域
function toggleSection(sectionId) {
    const content = document.getElementById(sectionId + '-content');
    const arrow = document.getElementById(sectionId + '-arrow');

    if (content.classList.contains('active')) {
        content.classList.remove('active');
        arrow.classList.remove('rotate');
        arrow.textContent = '▼';
    } else {
        content.classList.add('active');
        arrow.classList.add('rotate');
        arrow.textContent = '▲';
    }
}

// 导出报告
function exportReport() {
    if (!scanResults) return;

    const report = {
        url: currentTab.url,
        timestamp: new Date().toISOString(),
        scanMode: scanResults.scanMode,
        score: scanResults.score,
        riskLevel: scanResults.riskLevel,
        issues: scanResults.issues,
        headers: scanResults.headers,
        backendStatus: backendStatus
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `headersense-report-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('报告已导出');
}

// 创建模态框
function createModal(title, content) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <h3>${title}</h3>
                <button class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
            </div>
        </div>
    `;

    const modalBody = overlay.querySelector('.modal-body');
    modalBody.appendChild(content);

    // 添加关闭事件
    overlay.querySelector('.modal-close').addEventListener('click', () => {
        overlay.remove();
    });

    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            overlay.remove();
        }
    });

    return overlay;
}

// 显示提示消息
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '1';
    }, 100);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => {
            if (document.body.contains(toast)) {
                document.body.removeChild(toast);
            }
        }, 300);
    }, 3000);
}