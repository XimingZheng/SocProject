#!/usr/bin/env python3
"""
Flask后端安全扫描服务器
为Chrome扩展提供多线程安全扫描服务
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import asyncio
import aiohttp
import threading
import queue
import time
import json
import logging
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from urllib.parse import urljoin, urlparse
import ssl
import socket
from datetime import datetime
import uuid
from werkzeug.serving import WSGIRequestHandler

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 禁用Flask的请求日志以减少噪音
class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        # 只记录错误请求
        if str(code).startswith('4') or str(code).startswith('5'):
            super().log_request(code, size)

app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 全局变量存储扫描任务
scan_tasks = {}
task_results = {}

@dataclass
class ScanResult:
    """扫描结果数据类"""
    scanner_name: str
    vulnerability_type: str
    risk_level: str  # high, medium, low
    title: str
    description: str
    evidence: str
    fix_suggestion: str
    url: str
    timestamp: str
    details: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class BaseScanner(ABC):
    """扫描器基类"""
    
    def __init__(self, name: str):
        self.name = name
        self.results = []
    
    @abstractmethod
    async def scan(self, session: aiohttp.ClientSession, url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
        """执行扫描"""
        pass

class HeaderScanner(BaseScanner):
    """HTTP响应头安全扫描器"""
    
    def __init__(self):
        super().__init__("Header Scanner")
        self.security_headers = {
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'description': '防止MIME类型嗅探攻击',
                'recommended_value': 'nosniff',
                'risk_level': 'medium',
                'explanation': '此头部防止浏览器对响应内容进行MIME类型猜测，避免恶意内容被执行',
                'fix_suggestion': '在服务器响应中添加 X-Content-Type-Options: nosniff'
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'description': '防止点击劫持(Clickjacking)攻击',
                'recommended_value': ['DENY', 'SAMEORIGIN'],
                'risk_level': 'high',
                'explanation': '此头部防止页面被嵌入到iframe中，避免点击劫持攻击',
                'fix_suggestion': '设置 X-Frame-Options: DENY 或 X-Frame-Options: SAMEORIGIN'
            },
            'content-security-policy': {
                'name': 'Content-Security-Policy',
                'description': '防止XSS和代码注入攻击',
                'risk_level': 'high',
                'explanation': '此头部定义了页面可以加载的资源，有效防止XSS攻击',
                'fix_suggestion': '配置适当的CSP策略，例如：default-src \'self\''
            },
            'strict-transport-security': {
                'name': 'Strict-Transport-Security',
                'description': '强制HTTPS连接',
                'risk_level': 'medium',
                'explanation': '此头部强制浏览器使用HTTPS连接，防止中间人攻击',
                'fix_suggestion': '设置 Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'description': '启用浏览器XSS防护',
                'recommended_value': '1; mode=block',
                'risk_level': 'low',
                'explanation': '此头部启用浏览器的XSS过滤器（已被CSP取代，但仍有价值）',
                'fix_suggestion': '设置 X-XSS-Protection: 1; mode=block'
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'description': '控制Referrer信息泄露',
                'recommended_value': ['strict-origin-when-cross-origin', 'no-referrer'],
                'risk_level': 'low',
                'explanation': '此头部控制浏览器发送referrer信息的策略，防止信息泄露',
                'fix_suggestion': '设置 Referrer-Policy: strict-origin-when-cross-origin'
            }
        }
    
    async def scan(self, session: aiohttp.ClientSession, url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
        results = []
        headers = response_data.get('headers', {})
        
        for header_key, header_config in self.security_headers.items():
            header_value = headers.get(header_key.lower())
            
            if not header_value:
                result = ScanResult(
                    scanner_name=self.name,
                    vulnerability_type='Missing Security Header',
                    risk_level=header_config['risk_level'],
                    title=f'缺少 {header_config["name"]} 响应头',
                    description=header_config['description'],
                    evidence=f'响应头中未找到 {header_key}',
                    fix_suggestion=header_config['fix_suggestion'],
                    url=url,
                    timestamp=datetime.now().isoformat(),
                    details={'header_name': header_key, 'expected_value': header_config.get('recommended_value')}
                )
                results.append(result)
            else:
                # 验证头部值是否正确配置
                validation_result = self._validate_header_value(header_key, header_value, header_config)
                if not validation_result['is_valid']:
                    result = ScanResult(
                        scanner_name=self.name,
                        vulnerability_type='Misconfigured Security Header',
                        risk_level=header_config['risk_level'],
                        title=f'{header_config["name"]} 配置不当',
                        description=header_config['description'],
                        evidence=f'{header_key}: {header_value} - {validation_result["issue"]}',
                        fix_suggestion=header_config['fix_suggestion'],
                        url=url,
                        timestamp=datetime.now().isoformat(),
                        details={'header_name': header_key, 'current_value': header_value, 'issue': validation_result['issue']}
                    )
                    results.append(result)
        
        return results
    
    def _validate_header_value(self, header_key: str, header_value: str, header_config: Dict) -> Dict[str, Any]:
        """验证响应头值"""
        if header_key == 'x-content-type-options':
            return {
                'is_valid': header_value.lower() == 'nosniff',
                'issue': '值应为 nosniff' if header_value.lower() != 'nosniff' else None
            }
        elif header_key == 'x-frame-options':
            valid_options = ['DENY', 'SAMEORIGIN']
            is_valid = any(option in header_value.upper() for option in valid_options)
            return {
                'is_valid': is_valid,
                'issue': '值应为 DENY 或 SAMEORIGIN' if not is_valid else None
            }
        elif header_key == 'content-security-policy':
            has_default_src = 'default-src' in header_value
            has_unsafe = "'unsafe-inline'" in header_value or "'unsafe-eval'" in header_value
            
            if not has_default_src:
                return {'is_valid': False, 'issue': '缺少 default-src 指令'}
            if has_unsafe:
                return {'is_valid': False, 'issue': '存在不安全的 unsafe-inline 或 unsafe-eval 指令'}
            return {'is_valid': True, 'issue': None}
        
        return {'is_valid': True, 'issue': None}

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

class SSLScanner(BaseScanner):
    """SSL/TLS安全扫描器"""
    
    def __init__(self):
        super().__init__("SSL Scanner")
    
    async def scan(self, session: aiohttp.ClientSession, url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
        results = []
        parsed_url = urlparse(url)
        
        if parsed_url.scheme != 'https':
            result = ScanResult(
                scanner_name=self.name,
                vulnerability_type='Insecure Protocol',
                risk_level='high',
                title='网站未使用HTTPS',
                description='网站使用HTTP协议，数据传输未加密',
                evidence=f'URL scheme: {parsed_url.scheme}',
                fix_suggestion='启用HTTPS并配置SSL证书',
                url=url,
                timestamp=datetime.now().isoformat()
            )
            results.append(result)
        
        return results

class ThreadSafeScannerManager:
    """线程安全的扫描器管理器"""
    
    def __init__(self):
        self.scanners = []
        self._register_scanners()
    
    def _register_scanners(self):
        """注册所有扫描器"""
        self.scanners = [
            HeaderScanner(),
            XSSScanner(),
            SQLInjectionScanner(),
            SSLScanner()
        ]
    
    async def scan_website(self, url: str, headers_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """扫描网站"""
        logger.info(f"开始扫描网站: {url}")
        start_time = time.time()
        
        # 创建HTTP会话
        timeout = aiohttp.ClientTimeout(total=15)
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # 获取网站基本信息
            try:
                if headers_data:
                    # 如果前端已经提供了headers数据，直接使用
                    response_data = {
                        'headers': headers_data,
                        'content': '',
                        'status': 200,
                        'url': url
                    }
                    # 仍然获取页面内容用于其他扫描
                    try:
                        async with session.get(url) as response:
                            response_data['content'] = await response.text()
                            response_data['status'] = response.status
                    except:
                        pass
                else:
                    response_data = await self._fetch_website_data(session, url)
            except Exception as e:
                logger.error(f"获取网站数据失败: {e}")
                return {
                    'url': url,
                    'error': str(e),
                    'scan_time': time.time() - start_time,
                    'results': []
                }
            
            # 并发执行所有扫描器
            tasks = []
            for scanner in self.scanners:
                task = asyncio.create_task(
                    self._run_scanner_safe(scanner, session, url, response_data)
                )
                tasks.append(task)
            
            # 等待所有扫描完成
            all_results = []
            completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(completed_tasks):
                if isinstance(result, Exception):
                    logger.error(f"扫描器 {self.scanners[i].name} 出错: {result}")
                else:
                    all_results.extend(result)
        
        scan_time = time.time() - start_time
        
        # 生成扫描报告
        report = self._generate_report(url, all_results, scan_time)
        logger.info(f"扫描完成，耗时 {scan_time:.2f} 秒，发现 {len(all_results)} 个问题")
        
        return report
    
    async def _fetch_website_data(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """获取网站数据"""
        async with session.get(url) as response:
            content = await response.text()
            headers = dict(response.headers)
            
            return {
                'content': content,
                'headers': headers,
                'status': response.status,
                'url': str(response.url)
            }
    
    async def _run_scanner_safe(self, scanner: BaseScanner, session: aiohttp.ClientSession, 
                               url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
        """安全运行扫描器"""
        try:
            logger.info(f"运行扫描器: {scanner.name}")
            results = await scanner.scan(session, url, response_data)
            logger.info(f"扫描器 {scanner.name} 完成，发现 {len(results)} 个问题")
            return results
        except Exception as e:
            logger.error(f"扫描器 {scanner.name} 执行失败: {e}")
            return []
    
    def _generate_report(self, url: str, results: List[ScanResult], scan_time: float) -> Dict[str, Any]:
        """生成扫描报告"""
        # 按风险等级分类
        high_risk = [r for r in results if r.risk_level == 'high']
        medium_risk = [r for r in results if r.risk_level == 'medium']
        low_risk = [r for r in results if r.risk_level == 'low']
        
        # 计算安全评分
        total_possible_score = 100
        penalty_score = len(high_risk) * 20 + len(medium_risk) * 10 + len(low_risk) * 5
        security_score = max(0, total_possible_score - penalty_score)
        
        # 确定整体风险等级
        if len(high_risk) >= 2 or security_score < 40:
            overall_risk = 'high'
        elif len(high_risk) >= 1 or len(medium_risk) >= 2 or security_score < 70:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'url': url,
            'scan_time': scan_time,
            'timestamp': datetime.now().isoformat(),
            'security_score': security_score,
            'overall_risk_level': overall_risk,
            'total_issues': len(results),
            'statistics': {
                'high_risk': len(high_risk),
                'medium_risk': len(medium_risk),
                'low_risk': len(low_risk)
            },
            'results': [result.to_dict() for result in results],
            'summary': self._generate_summary(results, overall_risk)
        }
    
    def _generate_summary(self, results: List[ScanResult], overall_risk: str) -> str:
        """生成扫描摘要"""
        if not results:
            return "✅ 未发现明显的安全问题"
        
        high_count = len([r for r in results if r.risk_level == 'high'])
        medium_count = len([r for r in results if r.risk_level == 'medium'])
        low_count = len([r for r in results if r.risk_level == 'low'])
        
        summary_parts = []
        if high_count > 0:
            summary_parts.append(f"{high_count} 个高风险问题")
        if medium_count > 0:
            summary_parts.append(f"{medium_count} 个中风险问题")
        if low_count > 0:
            summary_parts.append(f"{low_count} 个低风险问题")
        
        return f"发现 {', '.join(summary_parts)}"

# Flask API路由
@app.route('/api/scan', methods=['POST'])
def start_scan():
    """启动扫描任务"""
    try:
        data = request.get_json()
        url = data.get('url')
        headers_data = data.get('headers', {})
        
        if not url:
            return jsonify({'error': '缺少URL参数'}), 400
        
        # 生成任务ID
        task_id = str(uuid.uuid4())
        
        # 创建扫描任务
        def run_scan_task():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                scanner_manager = ThreadSafeScannerManager()
                result = loop.run_until_complete(
                    scanner_manager.scan_website(url, headers_data)
                )
                
                task_results[task_id] = {
                    'status': 'completed',
                    'result': result
                }
                
                loop.close()
                
            except Exception as e:
                logger.error(f"扫描任务 {task_id} 失败: {e}")
                task_results[task_id] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        # 在后台线程中运行扫描
        scan_thread = threading.Thread(target=run_scan_task)
        scan_thread.daemon = True
        scan_thread.start()
        
        # 存储任务信息
        scan_tasks[task_id] = {
            'status': 'running',
            'url': url,
            'start_time': time.time(),
            'thread': scan_thread
        }
        
        task_results[task_id] = {'status': 'running'}
        
        return jsonify({
            'task_id': task_id,
            'status': 'started',
            'message': '扫描任务已启动'
        })
        
    except Exception as e:
        logger.error(f"启动扫描任务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/status/<task_id>', methods=['GET'])
def get_scan_status(task_id):
    """获取扫描任务状态"""
    try:
        if task_id not in task_results:
            return jsonify({'error': '任务不存在'}), 404
        
        task_result = task_results[task_id]
        task_info = scan_tasks.get(task_id, {})
        
        response = {
            'task_id': task_id,
            'status': task_result['status']
        }
        
        if task_result['status'] == 'completed':
            response['result'] = task_result['result']
            # 清理完成的任务
            if task_id in scan_tasks:
                del scan_tasks[task_id]
            del task_results[task_id]
        elif task_result['status'] == 'failed':
            response['error'] = task_result['error']
            # 清理失败的任务
            if task_id in scan_tasks:
                del scan_tasks[task_id]
            del task_results[task_id]
        elif task_result['status'] == 'running':
            response['elapsed_time'] = time.time() - task_info.get('start_time', time.time())
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"获取任务状态失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/quick', methods=['POST'])
def quick_scan():
    """快速扫描（仅响应头检查）"""
    try:
        data = request.get_json()
        url = data.get('url')
        headers_data = data.get('headers', {})
        
        if not url:
            return jsonify({'error': '缺少URL参数'}), 400
        
        # 只运行Header扫描器进行快速检查
        scanner = HeaderScanner()
        
        async def quick_scan_task():
            response_data = {
                'headers': headers_data,
                'content': '',
                'status': 200,
                'url': url
            }
            return await scanner.scan(None, url, response_data)
        
        # 运行快速扫描
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(quick_scan_task())
        loop.close()
        
        # 生成简化报告
        high_risk = [r for r in results if r.risk_level == 'high']
        medium_risk = [r for r in results if r.risk_level == 'medium']
        low_risk = [r for r in results if r.risk_level == 'low']
        
        security_score = max(0, 100 - (len(high_risk) * 20 + len(medium_risk) * 10 + len(low_risk) * 5))
        
        if len(high_risk) >= 2 or security_score < 40:
            overall_risk = 'high'
        elif len(high_risk) >= 1 or len(medium_risk) >= 2 or security_score < 70:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return jsonify({
            'url': url,
            'scan_type': 'quick',
            'security_score': security_score,
            'risk_level': overall_risk,
            'total_issues': len(results),
            'statistics': {
                'high_risk': len(high_risk),
                'medium_risk': len(medium_risk),
                'low_risk': len(low_risk)
            },
            'issues': [result.to_dict() for result in results],
            'summary': f"发现 {len(results)} 个响应头安全问题" if results else "响应头配置良好"
        })
        
    except Exception as e:
        logger.error(f"快速扫描失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'active_tasks': len(scan_tasks)
    })

@app.route('/api/scanners', methods=['GET'])
def get_available_scanners():
    """获取可用的扫描器列表"""
    scanners_info = [
        {
            'name': 'Header Scanner',
            'description': '检测HTTP安全响应头配置',
            'vulnerability_types': ['Missing Security Header', 'Misconfigured Security Header']
        },
        {
            'name': 'XSS Scanner',
            'description': '检测跨站脚本攻击漏洞',
            'vulnerability_types': ['Cross-Site Scripting (XSS)']
        },
        {
            'name': 'SQL Injection Scanner',
            'description': '检测SQL注入漏洞',
            'vulnerability_types': ['SQL Injection']
        },
        {
            'name': 'SSL Scanner',
            'description': '检测SSL/TLS配置问题',
            'vulnerability_types': ['Insecure Protocol']
        }
    ]
    
    return jsonify({
        'scanners': scanners_info,
        'total_scanners': len(scanners_info)
    })

# 清理过期任务的后台线程
def cleanup_expired_tasks():
    """清理过期的任务"""
    while True:
        try:
            current_time = time.time()
            expired_tasks = []
            
            for task_id, task_info in scan_tasks.items():
                # 清理运行超过10分钟的任务
                if current_time - task_info.get('start_time', current_time) > 600:
                    expired_tasks.append(task_id)
            
            for task_id in expired_tasks:
                logger.info(f"清理过期任务: {task_id}")
                if task_id in scan_tasks:
                    del scan_tasks[task_id]
                if task_id in task_results:
                    del task_results[task_id]
            
            time.sleep(60)  # 每分钟清理一次
            
        except Exception as e:
            logger.error(f"清理任务时出错: {e}")
            time.sleep(60)

if __name__ == '__main__':
    # 启动清理线程
    cleanup_thread = threading.Thread(target=cleanup_expired_tasks)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    
    print("🔒 HeaderSense 后端服务器启动中...")
    print("=" * 50)
    print("API端点:")
    print("  POST /api/scan - 启动完整扫描")
    print("  POST /api/scan/quick - 快速响应头扫描")
    print("  GET  /api/scan/status/<task_id> - 获取扫描状态")
    print("  GET  /api/health - 健康检查")
    print("  GET  /api/scanners - 获取可用扫描器")
    print("=" * 50)
    print("服务器运行在: http://localhost:5000")
    print("Chrome扩展可以通过API与后端通信")
    
    app.run(
        host='localhost',
        port=5000,
        debug=False,
        threaded=True,
        request_handler=QuietWSGIRequestHandler
    )