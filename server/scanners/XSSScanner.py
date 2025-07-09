from asyncio.log import logger
import re
import aiohttp
import logging
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urljoin

from scanners.BaseScanner import BaseScanner, ScanResult


class XSSScanner(BaseScanner):
    """XSS漏洞扫描器"""
    
    def __init__(self):
        super().__init__("XSS Scanner")
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>"
        ]
    
    async def scan(self, session: aiohttp.ClientSession, url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
        results = []
        html_content = response_data.get('content', '')
        
        # 查找表单进行测试
        forms = self._extract_forms(html_content)
        
        for form in forms[:3]:  # 限制测试表单数量
            for payload in self.xss_payloads[:3]:  # 限制payload数量以减少请求
                try:
                    vulnerable = await self._test_xss_payload(session, url, form, payload)
                    if vulnerable:
                        result = ScanResult(
                            scanner_name=self.name,
                            vulnerability_type='Cross-Site Scripting (XSS)',
                            risk_level='high',
                            title=f'发现XSS漏洞',
                            description='页面存在跨站脚本攻击漏洞，可能导致用户数据泄露',
                            evidence=f'Payload: {payload}',
                            fix_suggestion='对用户输入进行严格的过滤和编码，使用CSP防护',
                            url=url,
                            timestamp=datetime.now().isoformat(),
                            details={'form_action': form.get('action', ''), 'payload': payload}
                        )
                        results.append(result)
                        break  # 发现漏洞后跳出payload循环
                except Exception as e:
                    logger.error(f"XSS测试出错: {e}")
        
        return results
    
    def _extract_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """提取HTML中的表单"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        
        form_matches = re.finditer(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        for form_match in form_matches:
            form_html = form_match.group(0)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            forms.append({
                'action': action_match.group(1) if action_match else '',
                'method': method_match.group(1) if method_match else 'GET',
                'inputs': inputs
            })
        
        return forms
    
    async def _test_xss_payload(self, session: aiohttp.ClientSession, base_url: str, form: Dict, payload: str) -> bool:
        """测试XSS payload"""
        try:
            form_url = urljoin(base_url, form['action']) if form['action'] else base_url
            data = {input_name: payload for input_name in form['inputs'][:2]}  # 限制参数数量
            
            if form['method'].upper() == 'POST':
                async with session.post(form_url, data=data, timeout=5) as response:
                    content = await response.text()
            else:
                async with session.get(form_url, params=data, timeout=5) as response:
                    content = await response.text()
            
            # 检查payload是否在响应中未经编码地出现
            return payload in content
            
        except Exception:
            return False