import asyncio
import time
import logging
from datetime import datetime
from typing import Dict, List, Any

import aiohttp

from scanners.BaseScanner import BaseScanner, ScanResult
from scanners.HeaderScanner import HeaderScanner
from scanners.XSSScanner import XSSScanner
from scanners.SQLInjectionScanner import SQLInjectionScanner
from scanners.SSLScanner import SSLScanner

logger = logging.getLogger(__name__)

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