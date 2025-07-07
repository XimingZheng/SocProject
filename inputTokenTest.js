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
            // 弹出警告弹窗
            alert("Risk detected in HTML! This page has been blocked for your safety.");

            // 通知 block.js 进行页面拦截
            chrome.runtime.sendMessage({ action: "blockPage" });
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