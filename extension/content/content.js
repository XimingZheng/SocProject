// content.js

let currentSecurityState = null;

// Listen for messages from background
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

// Show security warning banner
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
    <strong>Security Warning:</strong> This website is missing important security configurations and may pose a risk.
    <button id="headersense-details" style="
      background: rgba(255,255,255,0.2);
      border: 1px solid rgba(255,255,255,0.3);
      color: white;
      padding: 4px 12px;
      margin-left: 15px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    ">Details</button>
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

    // Add event listeners
    document.getElementById('headersense-details').addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'openPopup' });
    });

    document.getElementById('headersense-dismiss').addEventListener('click', () => {
        warningDiv.remove();
    });

    // Auto-hide after 10 seconds
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

// Notify background that content script is ready
chrome.runtime.sendMessage({ action: 'contentScriptReady' });
