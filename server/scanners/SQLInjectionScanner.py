import re
import aiohttp
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Any
from urllib.parse import urljoin

from scanners.BaseScanner import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):
    """SQL注入漏洞扫描器"""
    
    def __init__(self):
        super().__init__("SQL Injection Scanner")
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--"
        ]
        self.sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"Oracle.*ORA-\d+",
            r"SQLite.*error"
        ]
    
    async def scan(self, session: aiohttp.ClientSession, url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
        results = []
        html_content = response_data.get('content', '')
        
        # 查找表单进行测试
        forms = self._extract_forms(html_content)
        
        for form in forms[:2]:  # 限制测试表单数量
            for payload in self.sql_payloads:
                try:
                    vulnerable, error_msg = await self._test_sql_payload(session, url, form, payload)
                    if vulnerable:
                        result = ScanResult(
                            scanner_name=self.name,
                            vulnerability_type='SQL Injection',
                            risk_level='high',
                            title='发现SQL注入漏洞',
                            description='页面存在SQL注入漏洞，可能导致数据库信息泄露',
                            evidence=f'Payload: {payload}, Error: {error_msg}',
                            fix_suggestion='使用参数化查询或预编译语句，对用户输入进行严格验证',
                            url=url,
                            timestamp=datetime.now().isoformat(),
                            details={'form_action': form.get('action', ''), 'payload': payload, 'error': error_msg}
                        )
                        results.append(result)
                        break
                except Exception as e:
                    logger.error(f"SQL注入测试出错: {e}")
        
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
    
    async def _test_sql_payload(self, session: aiohttp.ClientSession, base_url: str, form: Dict, payload: str) -> Tuple[bool, str]:
        """测试SQL注入payload"""
        try:
            form_url = urljoin(base_url, form['action']) if form['action'] else base_url
            data = {input_name: payload for input_name in form['inputs'][:2]}
            
            if form['method'].upper() == 'POST':
                async with session.post(form_url, data=data, timeout=5) as response:
                    content = await response.text()
            else:
                async with session.get(form_url, params=data, timeout=5) as response:
                    content = await response.text()
            
            # 检查是否有SQL错误信息
            for pattern in self.sql_error_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return True, match.group(0)
            
            return False, ""
            
        except Exception:
            return False, ""