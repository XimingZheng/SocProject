// block.js

// 监听来自 inputTokenTest.js 或 headerAnalyze.js 的消息
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    // 检查消息的 action 是否为 "blockPage"
    if (request.action === "blockPage") {
        // 拦截页面加载
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            const activeTab = tabs[0];
            if (activeTab) {
                // 提示用户页面已被拦截，并提供安全页面选项
                const userResponse = confirm(
                    "This page has been blocked due to potential security risks. Would you like to be redirected to a safe page?"
                );

                if (userResponse) {
                    // 用户选择重定向到安全页面
                    chrome.tabs.update(activeTab.id, {
                        url: "https://www.example.com/safe-page"
                    });
                } else {
                    // 用户选择关闭页面
                    chrome.tabs.remove(activeTab.id);
                }
            }
        });

        // 可选：确认拦截操作已完成
        sendResponse({ message: "Page blocked successfully." });
    }
});