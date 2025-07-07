// inputTokenTest.js

// 监听来自 htmlGet.js 的消息
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    // 检查消息的 action 是否为 "analyzeHTML"
    if (request.action === "analyzeHTML") {
        // 打印接收到的 HTML 内容
        console.log("Received HTML content from htmlGet.js:", request.htmlContent);

        // 对 HTML 内容进行分析
        const riskDetected = analyzeHTML(request.htmlContent);

        // 如果检测到风险，触发弹窗并尝试拦截页面
      if (riskDetected) {
    console.warn("Risk detected in HTML! Blocking the page.");
    
    // Create a custom modal instead of using the default alert
    let modal = document.createElement('div');
    modal.style.position = 'fixed';
    modal.style.top = '50%';
    modal.style.left = '50%';
    modal.style.transform = 'translate(-50%, -50%)';
    modal.style.padding = '20px';
    modal.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
    modal.style.color = 'white';
    modal.style.borderRadius = '10px';
    modal.style.zIndex = '9999';
    
    // 弹窗
    let message = document.createElement('p');
    message.textContent = "Risk detected in HTML! Do you want to block this page?";
    modal.appendChild(message);
    
    // blockButton
    let blockButton = document.createElement('button');
    blockButton.textContent = 'Block Page';
    blockButton.style.marginRight = '10px';
    blockButton.style.padding = '10px';
    blockButton.style.backgroundColor = 'red';
    blockButton.style.color = 'white';
    blockButton.style.border = 'none';
    blockButton.style.cursor = 'pointer';
    
    // cancerbutton
    let cancelButton = document.createElement('button');
    cancelButton.textContent = 'Cancel';
    cancelButton.style.padding = '10px';
    cancelButton.style.backgroundColor = 'gray';
    cancelButton.style.color = 'white';
    cancelButton.style.border = 'none';
    cancelButton.style.cursor = 'pointer';
    
    // Append buttons to modal
    modal.appendChild(blockButton);
    modal.appendChild(cancelButton);
    
    // Append modal to body
    document.body.appendChild(modal);
    
    // Block page if the user clicks "Block Page"
    blockButton.addEventListener('click', function() {
        chrome.runtime.sendMessage({ action: "blockPage" });
        document.body.removeChild(modal); // Remove modal after action
    });

    // Do nothing if the user clicks "Cancel"
    cancelButton.addEventListener('click', function() {
        document.body.removeChild(modal); // Simply remove the modal
    });
}


        // 可选：确认信息已接收
        sendResponse({ message: "HTML content received and analyzed." });
    }
});

// 示例分析函数
function analyzeHTML(htmlContent) {
    // 这里可以实现对 HTML 内容的分析逻辑
    // 示例：检测是否存在某些可疑的关键词或模式
    const suspiciousKeywords = ["malware", "phishing", "scam"];
    for (const keyword of suspiciousKeywords) {
        if (htmlContent.includes(keyword)) {
            console.log("Suspicious keyword detected:", keyword);
            return true; // 检测到风险
        }
    }

    // 检查 HTML 中的 input 标签是否存在潜在风险
    const inputTags = htmlContent.match(/<input[^>]*>/gi) || [];
    for (const inputTag of inputTags) {
        if (inputTag.includes("type='password'") && inputTag.includes("autocomplete='off'")) {
            console.log("Suspicious input tag detected:", inputTag);
            return true; // 检测到风险
        }
    }

    return false; // 未检测到风险
}
