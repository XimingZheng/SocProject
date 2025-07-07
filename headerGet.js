// headerGet.js

// 监听浏览器的请求，获取请求头信息
chrome.webRequest.onBeforeSendHeaders.addListener(
function(details) {
  // 获取当前请求的请求头
  const headers = details.requestHeaders;

  // 将请求头信息传递给 headerAnalyze.js
  chrome.runtime.sendMessage({
  action: "analyzeHeaders",
  headers: headers
});

// 返回请求头，不修改请求头
return { cancel: false, requestHeaders: headers };
},
{ urls: ["<all_urls>"] }, // 监听所有网址的请求
["blocking", "requestHeaders"] // 需要的额外权限
);

console.log("headerGet.js is running and listening for headers.");