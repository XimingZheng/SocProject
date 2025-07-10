import aiohttp
from scanners.BaseScanner import BaseScanner, ScanResult
from datetime import datetime
from typing import Dict, List, Any
import re

class HeaderScanner(BaseScanner):
    """HTTP Response Header Security Scanner with Penalty-based Scoring"""
    
    def __init__(self):
        super().__init__("Header Scanner")
        # 🔥 关键：这里必须定义penalty配置，后端评分会使用这些值
        self.security_headers = {
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'description': 'Prevent MIME type sniffing attacks',
                'recommended_value': 'nosniff',
                'risk_level': 'medium',
                'explanation': 'This header prevents browsers from guessing MIME types to avoid executing malicious content.',
                'fix_suggestion': 'Add X-Content-Type-Options: nosniff to the server response.',
                'missing_penalty': 6,
                'misconfigured_penalty': 3
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'description': 'Prevent Clickjacking attacks',
                'recommended_value': ['DENY', 'SAMEORIGIN'],
                'risk_level': 'high',
                'explanation': 'This header prevents the page from being embedded in iframes to avoid Clickjacking.',
                'fix_suggestion': 'Set X-Frame-Options to DENY or SAMEORIGIN.',
                'missing_penalty': 10,
                'misconfigured_penalty': 5
            },
            'content-security-policy': {
                'name': 'Content-Security-Policy',
                'description': 'Prevent XSS and code injection attacks',
                'risk_level': 'high',
                'explanation': 'This header defines the resources allowed on the page to mitigate XSS.',
                'fix_suggestion': 'Configure a proper CSP policy, e.g., default-src \'self\'',
                'missing_penalty': 25,          # 🔥 CSP缺失惩罚最重
                'misconfigured_penalty': 8,     # 一般配置错误
                'weak_csp_penalty': 5,          # 弱CSP配置
                'incomplete_csp_penalty': 12,   # 不完整CSP配置
                'meta_tag_penalty': 4           # Meta标签设置
            },
            'strict-transport-security': {
                'name': 'Strict-Transport-Security',
                'description': 'Enforce HTTPS connection',
                'risk_level': 'medium',
                'explanation': 'This header forces browsers to use HTTPS to prevent man-in-the-middle attacks.',
                'fix_suggestion': 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains.',
                'missing_penalty': 6,
                'misconfigured_penalty': 3
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'description': 'Enable browser XSS protection',
                'recommended_value': '1; mode=block',
                'risk_level': 'low',
                'explanation': 'This header enables browser XSS filter (deprecated but still useful).',
                'fix_suggestion': 'Set X-XSS-Protection: 1; mode=block',
                'missing_penalty': 3,
                'misconfigured_penalty': 1
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'description': 'Control referrer information leakage',
                'recommended_value': ['strict-origin-when-cross-origin', 'no-referrer'],
                'risk_level': 'low',
                'explanation': 'This header controls how much referrer information is sent to reduce information leakage.',
                'fix_suggestion': 'Set Referrer-Policy: strict-origin-when-cross-origin.',
                'missing_penalty': 3,
                'misconfigured_penalty': 1
            }
        }
    
    def get_max_possible_penalty(self) -> int:
        """获取最大可能惩罚分数"""
        return sum(config['missing_penalty'] for config in self.security_headers.values())
    
    async def scan(self, session: aiohttp.ClientSession, url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
        results = []
        headers = response_data.get('headers', {})
        
        # 标准化头部键名
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        
        print(f"[HeaderScanner] 🔍 扫描URL: {url}")
        print(f"[HeaderScanner] 📋 检测到的头部: {list(normalized_headers.keys())}")
        
        for header_key, header_config in self.security_headers.items():
            header_value = normalized_headers.get(header_key.lower())
            
            if header_key == 'content-security-policy':
                print(f"[HeaderScanner] 🛡️ CSP检查: {header_value}")
            
            if not header_value:
                # 🔥 检查CSP是否通过meta标签设置
                if header_key == 'content-security-policy':
                    meta_csp = self._extract_meta_csp(response_data.get('content', ''))
                    if meta_csp:
                        print(f"[HeaderScanner] 📋 发现meta CSP: {meta_csp}")
                        result = self._create_result(
                            url=url,
                            header_config=header_config,
                            vuln_type='CSP Set via Meta Tag',
                            risk_level='low',
                            title=f'{header_config["name"]} set via meta tag',
                            description=f'{header_config["description"]} (found in meta tag)',
                            evidence=f'CSP found in meta tag: {meta_csp[:100]}...' if len(meta_csp) > 100 else f'CSP found in meta tag: {meta_csp}',
                            fix_suggestion='CSP is set via meta tag. Consider moving to HTTP response headers for better security.',
                            penalty_score=header_config['meta_tag_penalty'],
                            penalty_type='meta_tag',
                            current_value=meta_csp
                        )
                        results.append(result)
                        continue
                
                # 🔥 头部完全缺失
                penalty_score = header_config['missing_penalty']
                print(f"[HeaderScanner] ❌ {header_key} 缺失，惩罚: {penalty_score}分")
                
                result = self._create_result(
                    url=url,
                    header_config=header_config,
                    vuln_type='Missing Security Header',
                    risk_level=header_config['risk_level'],
                    title=f'Missing {header_config["name"]} header',
                    description=header_config['description'],
                    evidence=f'{header_key} header not found in response',
                    fix_suggestion=header_config['fix_suggestion'],
                    penalty_score=penalty_score,
                    penalty_type='missing'
                )
                results.append(result)
                
            else:
                # 🔥 头部存在，验证配置
                validation_result = self._validate_header_value(header_key, header_value, header_config)
                if not validation_result['is_valid']:
                    # 计算惩罚分数
                    penalty_score = self._calculate_penalty(header_key, header_config, validation_result)
                    severity = validation_result.get('severity', 'moderate')
                    
                    print(f"[HeaderScanner] ⚙️ {header_key} 配置不当，严重程度: {severity}, 惩罚: {penalty_score}分")
                    
                    result = self._create_result(
                        url=url,
                        header_config=header_config,
                        vuln_type='Misconfigured Security Header',
                        risk_level=self._get_adjusted_risk_level(header_config['risk_level'], severity),
                        title=f'{header_config["name"]} is misconfigured',
                        description=header_config['description'],
                        evidence=f'{header_key}: {header_value} - {validation_result["issue"]}',
                        fix_suggestion=header_config['fix_suggestion'],
                        penalty_score=penalty_score,
                        penalty_type='misconfigured',
                        current_value=header_value,
                        severity=severity
                    )
                    results.append(result)
                else:
                    print(f"[HeaderScanner] ✅ {header_key} 配置正确")
        
        print(f"[HeaderScanner] 📊 总共发现 {len(results)} 个问题")
        return results
    
    def _create_result(self, url: str, header_config: Dict, vuln_type: str, risk_level: str, 
                      title: str, description: str, evidence: str, fix_suggestion: str,
                      penalty_score: int, penalty_type: str, current_value: str = None, 
                      severity: str = 'moderate') -> ScanResult:
        """创建扫描结果"""
        return ScanResult(
            scanner_name=self.name,
            vulnerability_type=vuln_type,
            risk_level=risk_level,
            title=title,
            description=description,
            evidence=evidence,
            fix_suggestion=fix_suggestion,
            url=url,
            timestamp=datetime.now().isoformat(),
            details={
                'header_name': header_config['name'],
                'current_value': current_value,
                'penalty_score': penalty_score,
                'penalty_type': penalty_type,
                'severity': severity
            }
        )
    
    def _extract_meta_csp(self, html_content: str) -> str:
        """从HTML内容中提取meta标签中的CSP"""
        if not html_content:
            return None
            
        # 查找CSP meta标签
        csp_pattern = r'<meta\s+http-equiv=["\']?content-security-policy["\']?\s+content=["\']([^"\']+)["\']'
        match = re.search(csp_pattern, html_content, re.IGNORECASE)
        
        if match:
            return match.group(1)
        
        return None
    
    def _calculate_penalty(self, header_key: str, header_config: Dict, validation_result: Dict) -> int:
        """🔥 关键：计算惩罚分数"""
        if header_key == 'content-security-policy':
            # CSP特殊处理：根据严重程度分配不同惩罚
            severity = validation_result.get('severity', 'moderate')
            
            if severity == 'critical':
                return header_config.get('incomplete_csp_penalty', 12)
            elif severity == 'major':
                return header_config.get('misconfigured_penalty', 8)
            elif severity == 'moderate':
                return header_config.get('weak_csp_penalty', 5)
            else:  # minor
                return 2
        else:
            return header_config.get('misconfigured_penalty', 3)
    
    def _get_adjusted_risk_level(self, original_risk: str, severity: str) -> str:
        """根据严重程度调整风险等级"""
        if severity == 'critical':
            return original_risk  # 保持原始风险等级
        elif severity == 'major':
            return original_risk if original_risk != 'low' else 'medium'
        else:
            # 配置问题降低一个风险等级
            if original_risk == 'high':
                return 'medium'
            elif original_risk == 'medium':
                return 'low'
            else:
                return 'low'
    
    def _validate_header_value(self, header_key: str, header_value: str, header_config: Dict) -> Dict[str, Any]:
        """验证响应头值"""
        if header_key == 'x-content-type-options':
            return {
                'is_valid': header_value.lower() == 'nosniff',
                'issue': 'Expected value is "nosniff"' if header_value.lower() != 'nosniff' else None
            }
        elif header_key == 'x-frame-options':
            valid_options = ['DENY', 'SAMEORIGIN']
            is_valid = any(option in header_value.upper() for option in valid_options)
            return {
                'is_valid': is_valid,
                'issue': 'Expected value is DENY or SAMEORIGIN' if not is_valid else None
            }
        elif header_key == 'content-security-policy':
            return self._validate_csp(header_value)
        elif header_key == 'strict-transport-security':
            return self._validate_hsts(header_value)
        elif header_key == 'x-xss-protection':
            valid_values = ['1', '1; mode=block']
            return {
                'is_valid': header_value in valid_values,
                'issue': 'Recommended setting is 1; mode=block' if header_value not in valid_values else None
            }
        elif header_key == 'referrer-policy':
            valid_policies = [
                'no-referrer', 'no-referrer-when-downgrade', 'origin',
                'origin-when-cross-origin', 'same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'unsafe-url'
            ]
            return {
                'is_valid': header_value in valid_policies,
                'issue': 'Invalid Referrer-Policy value' if header_value not in valid_policies else None
            }
        
        return {'is_valid': True, 'issue': None}
    
    def _validate_csp(self, csp_value: str) -> Dict[str, Any]:
        """验证CSP配置"""
        if not csp_value or csp_value.strip() == '':
            return {
                'is_valid': False,
                'issue': 'CSP value is empty',
                'severity': 'critical'
            }
        
        csp_lower = csp_value.lower()
        directives = [d.strip() for d in csp_value.split(';') if d.strip()]
        
        # 检查关键指令
        has_default_src = any(d.startswith('default-src') for d in directives)
        has_script_src = any(d.startswith('script-src') for d in directives)
        
        # 检查不安全的指令
        has_unsafe_inline = "'unsafe-inline'" in csp_lower
        has_unsafe_eval = "'unsafe-eval'" in csp_lower
        has_wildcard = '*' in csp_lower and "'self'" not in csp_lower
        
        # 评估严重程度
        issues = []
        severity = 'minor'
        
        # 关键缺失（严重问题）
        if not has_default_src and not has_script_src:
            issues.append('Missing default-src or script-src directive')
            severity = 'critical'
        elif not has_default_src:
            issues.append('Missing default-src directive')
            severity = 'major'
        
        # 极不安全组合（严重问题）
        if has_unsafe_inline and has_unsafe_eval and has_wildcard:
            issues.append('CSP contains unsafe-inline, unsafe-eval, and wildcard - provides minimal protection')
            severity = 'critical'
        # 不安全指令组合（重大问题）
        elif has_unsafe_inline and has_unsafe_eval:
            issues.append('CSP contains both unsafe-inline and unsafe-eval, reducing security significantly')
            if severity not in ['critical', 'major']:
                severity = 'major'
        # 单个不安全指令（中等问题）
        elif has_unsafe_inline:
            issues.append("Contains 'unsafe-inline' directive, which reduces security")
            if severity == 'minor':
                severity = 'moderate'
        elif has_unsafe_eval:
            issues.append("Contains 'unsafe-eval' directive, which reduces security")
            if severity == 'minor':
                severity = 'moderate'
        
        # 通配符问题（轻微到中等问题）
        if has_wildcard:
            issues.append('Contains wildcard (*) without proper restrictions')
            if severity == 'minor':
                severity = 'moderate'
        
        if issues:
            return {
                'is_valid': False,
                'issue': '; '.join(issues),
                'severity': severity
            }
        
        return {'is_valid': True, 'issue': None}
    
    def _validate_hsts(self, hsts_value: str) -> Dict[str, Any]:
        """验证HSTS配置"""
        max_age_match = re.search(r'max-age=(\d+)', hsts_value)
        if not max_age_match:
            return {
                'is_valid': False,
                'issue': 'Missing max-age directive'
            }
        
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:  # 1 year
            return {
                'is_valid': False,
                'issue': 'max-age value too small, recommended at least 31536000 (1 year)'
            }
        
        return {'is_valid': True, 'issue': None}