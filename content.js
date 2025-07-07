// content.js

let currentSecurityState = null;

// 监听来自后台的消息
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'securityScanResult') {
        currentSecurityState = request.result;

        if (currentSecurityState.riskLevel === 'high') {
            showSecurityWarning();
        }

        sendResponse({ received: true });
    }
    return true;
});

// 显示安全警告
function showSecurityWarning() {
    if (document.getElementById('headersense-warning')) {
        return;
    }

    const warningDiv = document.createElement('div');
    warningDiv.id = 'headersense-warning';
    warningDiv.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: linear-gradient(135deg, #ff6b6b, #ff8e8e);
    color: white;
    padding: 12px 20px;
    text-align: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    z-index: 999999;
    border-bottom: 3px solid #ff5252;
  `;

    warningDiv.innerHTML = `
    <span style="margin-right: 10px;">⚠️</span>
    <strong>安全警告：</strong>此网站缺少重要的安全配置，可能存在安全风险
    <button id="headersense-details" style="
      background: rgba(255,255,255,0.2);
      border: 1px solid rgba(255,255,255,0.3);
      color: white;
      padding: 4px 12px;
      margin-left: 15px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    ">查看详情</button>
    <button id="headersense-dismiss" style="
      background: transparent;
      border: none;
      color: white;
      padding: 4px 8px;
      margin-left: 10px;
      cursor: pointer;
      font-size: 16px;
      opacity: 0.8;
    ">×</button>
  `;

    document.body.prepend(warningDiv);

    // 添加事件监听器
    document.getElementById('headersense-details').addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'openPopup' });
    });

    document.getElementById('headersense-dismiss').addEventListener('click', () => {
        warningDiv.remove();
    });

    // 自动隐藏
    setTimeout(() => {
        if (warningDiv.parentNode) {
            warningDiv.style.opacity = '0';
            warningDiv.style.transition = 'opacity 0.5s';
            setTimeout(() => {
                if (warningDiv.parentNode) {
                    warningDiv.remove();
                }
            }, 500);
        }
    }, 10000);
}

// 通知后台脚本内容脚本已准备好
chrome.runtime.sendMessage({ action: 'contentScriptReady' });