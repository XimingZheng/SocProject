
// htmlGet.js

// 获取当前页面的 HTML 内容
function getHTMLContent() {
    const htmlContent = document.documentElement.outerHTML; // 获取整个文档的 HTML
    return htmlContent;
}

// 将 HTML 内容发送给 inputTokenTest.js
function sendHTMLContentToAnalyzer(htmlContent) {
    // 使用消息传递将 HTML 内容发送给 inputTokenTest.js
    chrome.runtime.sendMessage({
        action: "analyzeHTML",
        htmlContent: htmlContent
    });
}

// 主函数，启动整个流程
function main() {
    const htmlContent = getHTMLContent(); // 获取 HTML 内容
    sendHTMLContentToAnalyzer(htmlContent); // 发送 HTML 内容
}

// 确保在页面加载完成后运行
window.onload = main;