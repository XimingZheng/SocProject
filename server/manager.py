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
    """线程安全的扫描器管理器 - 🔥 使用基于penalty和score的风险评估系统"""
    
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
        """扫描网站 - 使用penalty-based评分"""
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
        
        # 🔥 关键：使用penalty-based评分生成报告
        report = self._generate_penalty_based_report(url, all_results, scan_time)
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
    
    def _generate_penalty_based_report(self, url: str, results: List[ScanResult], scan_time: float) -> Dict[str, Any]:
        """🔥 关键：生成基于penalty的评分报告"""
        print(f"[ScannerManager] 🔍 开始生成penalty-based报告")
        
        # 按风险等级分类
        high_risk = [r for r in results if r.risk_level == 'high']
        medium_risk = [r for r in results if r.risk_level == 'medium']
        low_risk = [r for r in results if r.risk_level == 'low']
        
        # 🔥 关键：计算基于penalty的安全评分
        security_score = self._calculate_penalty_based_score(results)
        
        # 🔥 关键修复：基于评分确定整体风险等级，而不是issue数量
        overall_risk = self._determine_overall_risk_by_score(security_score, results)
        
        print(f"[ScannerManager] 📊 评分结果: {security_score}/100, 风险等级: {overall_risk}")
        
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
            'summary': self._generate_summary(results, overall_risk),
            'scoring_details': self._generate_scoring_details(results)
        }
    
    def _calculate_penalty_based_score(self, results: List[ScanResult]) -> int:
        """🔥 关键：计算基于penalty的安全评分"""
        total_penalty = 0
        
        # 获取HeaderScanner的最大可能惩罚
        header_scanner = next((s for s in self.scanners if isinstance(s, HeaderScanner)), None)
        if header_scanner:
            max_possible_penalty = header_scanner.get_max_possible_penalty()
        else:
            # 后备计算
            max_possible_penalty = 53  # 25+10+6+6+3+3
        
        print(f"[ScannerManager] 📊 最大可能惩罚分: {max_possible_penalty}")
        
        # 计算实际惩罚
        for result in results:
            penalty_score = 0
            
            # 🔥 关键：从结果的details中获取penalty_score
            if result.details and 'penalty_score' in result.details:
                penalty_score = result.details['penalty_score']
                print(f"[ScannerManager] ⚠️ {result.title}: {penalty_score}分惩罚")
            else:
                # 后备计算方法（如果details中没有penalty_score）
                if 'Header' in result.vulnerability_type:
                    if result.vulnerability_type == 'Missing Security Header':
                        if 'CSP' in result.title or 'Content-Security-Policy' in result.title:
                            penalty_score = 25
                        elif result.risk_level == 'high':
                            penalty_score = 10
                        elif result.risk_level == 'medium':
                            penalty_score = 6
                        else:
                            penalty_score = 3
                    elif result.vulnerability_type == 'Misconfigured Security Header':
                        if 'CSP' in result.title or 'Content-Security-Policy' in result.title:
                            severity = result.details.get('severity', 'moderate') if result.details else 'moderate'
                            if severity == 'critical':
                                penalty_score = 12
                            elif severity == 'major':
                                penalty_score = 8
                            elif severity == 'moderate':
                                penalty_score = 5
                            else:
                                penalty_score = 2
                        else:
                            if result.risk_level == 'high':
                                penalty_score = 5
                            elif result.risk_level == 'medium':
                                penalty_score = 3
                            else:
                                penalty_score = 1
                    elif result.vulnerability_type == 'CSP Set via Meta Tag':
                        penalty_score = 4
                else:
                    # 其他类型的漏洞（XSS, SQL注入等）
                    if result.risk_level == 'high':
                        penalty_score = 20
                    elif result.risk_level == 'medium':
                        penalty_score = 10
                    else:
                        penalty_score = 5
                
                print(f"[ScannerManager] ⚠️ {result.title}: {penalty_score}分惩罚 (后备计算)")
            
            total_penalty += penalty_score
        
        print(f"[ScannerManager] 📊 总惩罚分: {total_penalty}/{max_possible_penalty}")
        
        # 🔥 关键：使用与前端相同的评分公式
        if max_possible_penalty > 0:
            penalty_percentage = total_penalty / max_possible_penalty
            score = max(0, round(100 * (1 - penalty_percentage)))
        else:
            score = max(0, 100 - total_penalty)
        
        print(f"[ScannerManager] 🎯 最终评分: {score}/100")
        return score
    
    def _determine_overall_risk_by_score(self, security_score: int, results: List[ScanResult]) -> str:
        """🔥 关键修复：基于分数而非issue数量确定整体风险等级"""
        print(f"[ScannerManager] 🎯 基于分数计算风险等级: {security_score}")
        
        # 检查特殊情况：CSP完全缺失或严重配置错误
        missing_csp = any(
            ('CSP' in result.title or 'Content-Security-Policy' in result.title) and
            result.vulnerability_type == 'Missing Security Header'
            for result in results
        )
        
        critical_csp = any(
            ('CSP' in result.title or 'Content-Security-Policy' in result.title) and
            result.details and result.details.get('severity') == 'critical'
            for result in results
        )
        
        print(f"[ScannerManager] 🔍 特殊情况检查: 缺失CSP={missing_csp}, 严重CSP={critical_csp}")
        
        # 🔥 关键：主要基于分数判断，CSP问题作为特殊考虑
        if security_score < 45 or missing_csp or critical_csp:
            print(f"[ScannerManager] ❌ 高风险: 分数={security_score} < 45 或CSP严重问题")
            return 'high'
        elif security_score < 75:
            print(f"[ScannerManager] ⚠️ 中风险: 分数={security_score} 在45-75之间")
            return 'medium'
        else:
            print(f"[ScannerManager] ✅ 低风险: 分数={security_score} >= 75")
            return 'low'
    
    def _generate_summary(self, results: List[ScanResult], overall_risk: str) -> str:
        """生成扫描摘要"""
        if not results:
            return "✅ 未发现明显的安全问题"
        
        high_count = len([r for r in results if r.risk_level == 'high'])
        medium_count = len([r for r in results if r.risk_level == 'medium'])
        low_count = len([r for r in results if r.risk_level == 'low'])
        
        # 特别标注CSP问题
        csp_issues = [r for r in results if 'CSP' in r.title or 'Content-Security-Policy' in r.title]
        critical_csp = [r for r in csp_issues if r.details and r.details.get('severity') == 'critical']
        
        summary_parts = []
        if high_count > 0:
            summary_parts.append(f"{high_count} 个高风险问题")
        if medium_count > 0:
            summary_parts.append(f"{medium_count} 个中风险问题")
        if low_count > 0:
            summary_parts.append(f"{low_count} 个低风险问题")
        
        if critical_csp:
            summary_parts.append(f"{len(critical_csp)} 个严重CSP问题")
        
        return f"发现 {', '.join(summary_parts)}"
    
    def _generate_scoring_details(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成评分详情"""
        penalty_breakdown = []
        total_penalty = 0
        
        for result in results:
            penalty_score = 0
            if result.details and 'penalty_score' in result.details:
                penalty_score = result.details['penalty_score']
            
            total_penalty += penalty_score
            
            penalty_breakdown.append({
                'title': result.title,
                'type': result.vulnerability_type,
                'penalty_score': penalty_score,
                'penalty_type': result.details.get('penalty_type', 'unknown') if result.details else 'unknown',
                'risk_level': result.risk_level,
                'severity': result.details.get('severity', 'moderate') if result.details else 'moderate'
            })
        
        # 获取HeaderScanner的最大可能惩罚
        header_scanner = next((s for s in self.scanners if isinstance(s, HeaderScanner)), None)
        max_possible_penalty = header_scanner.get_max_possible_penalty() if header_scanner else 53
        
        return {
            'total_penalty': total_penalty,
            'max_possible_penalty': max_possible_penalty,
            'penalty_percentage': round((total_penalty / max_possible_penalty * 100), 1) if max_possible_penalty > 0 else 0,
            'penalty_breakdown': penalty_breakdown,
            'csp_specific_issues': [
                item for item in penalty_breakdown 
                if 'CSP' in item['title'] or 'Content-Security-Policy' in item['title']
            ],
            'header_issues': [
                item for item in penalty_breakdown 
                if 'Header' in item['type']
            ],
            'other_issues': [
                item for item in penalty_breakdown 
                if 'Header' not in item['type']
            ]
        }