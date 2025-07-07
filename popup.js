// popup.js

let currentMode = 'user';
let scanResults = null;
let currentTab = null;

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

        // 开始扫描
        await performScan();
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
    document.getElementById('refreshBtn').addEventListener('click', performScan);

    // 开发者模式按钮
    document.getElementById('devRefreshBtn').addEventListener('click', performScan);
    document.getElementById('exportBtn').addEventListener('click', exportReport);

    // 折叠区域切换
    document.getElementById('toggleOverview').addEventListener('click', () => toggleSection('overview'));
    document.getElementById('toggleIssues').addEventListener('click', () => toggleSection('issues'));
    document.getElementById('toggleHeaders').addEventListener('click', () => toggleSection('headers'));
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

// 执行扫描
async function performScan() {
    showLoading();

    try {
        // 从后台获取扫描结果
        const results = await getScanResultsFromBackground();

        if (results) {
            scanResults = results;
            updateUserInterface(results);
        } else {
            showError('无法获取扫描结果');
        }

        hideLoading();
    } catch (error) {
        showError('扫描失败: ' + error.message);
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
                } else {
                    resolve(response);
                }
            }
        );
    });
}

// 更新用户界面
function updateUserInterface(results) {
    // 更新用户模式界面
    updateUserMode(results);

    // 更新开发者模式界面
    updateDeveloperMode(results);
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
    } else {
        badgeText = '安全配置良好';
        badgeIcon = '✅';
    }

    badge.innerHTML = `<span class="icon">${badgeIcon}</span><span>${badgeText}</span>`;

    // 更新评分
    scoreCircle.className = `score-circle ${results.riskLevel}`;
    scoreNumber.textContent = results.score;
    scoreDescription.textContent = `安全评分: ${results.score}/100`;

    // 更新统计信息
    const highCount = results.issues.filter(issue => issue.riskLevel === 'high').length;
    const mediumCount = results.issues.filter(issue => issue.riskLevel === 'medium').length;
    const lowCount = results.issues.filter(issue => issue.riskLevel === 'low').length;

    document.getElementById('highIssues').textContent = highCount;
    document.getElementById('mediumIssues').textContent = mediumCount;
    document.getElementById('lowIssues').textContent = lowCount;
}

// 更新开发者模式界面
function updateDeveloperMode(results) {
    // 更新统计信息
    const highCount = results.issues.filter(issue => issue.riskLevel === 'high').length;
    const mediumCount = results.issues.filter(issue => issue.riskLevel === 'medium').length;
    const lowCount = results.issues.filter(issue => issue.riskLevel === 'low').length;

    document.getElementById('dev-high').textContent = highCount;
    document.getElementById('dev-medium').textContent = mediumCount;
    document.getElementById('dev-low').textContent = lowCount;

    // 更新问题列表
    const issuesList = document.getElementById('issuesList');
    issuesList.innerHTML = '';

    if (results.issues.length === 0) {
        issuesList.innerHTML = '<div class="empty-state"><div class="icon">🎉</div><div>未发现安全问题</div></div>';
    } else {
        results.issues.forEach(issue => {
            const issueElement = document.createElement('div');
            issueElement.className = `issue-item ${issue.riskLevel}`;
            issueElement.innerHTML = `
                <div class="issue-title">${issue.header}: ${issue.title}</div>
                <div class="issue-description">${issue.description}</div>
                <div class="issue-fix"><strong>修复建议:</strong> ${issue.fixSuggestion}</div>
            `;
            issuesList.appendChild(issueElement);
        });
    }

    // 更新响应头列表
    const headersList = document.getElementById('headersList');
    headersList.innerHTML = '';

    Object.entries(results.headers).forEach(([name, value]) => {
        const headerElement = document.createElement('div');
        headerElement.className = 'header-item';
        headerElement.innerHTML = `
            <div class="header-name">${name}:</div>
            <div class="header-value">${value}</div>
        `;
        headersList.appendChild(headerElement);
    });
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

    if (content.style.display === 'none') {
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
    } else {
        content.classList.add('active');
        arrow.classList.add('rotate');
    }
}

// 导出报告
function exportReport() {
    if (!scanResults) return;

    const report = {
        url: currentTab.url,
        timestamp: new Date().toISOString(),
        score: scanResults.score,
        riskLevel: scanResults.riskLevel,
        issues: scanResults.issues,
        headers: scanResults.headers
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `header-scan-report-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('报告已导出');
}

// 显示提示消息
function showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '1';
    }, 100);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 2000);
}