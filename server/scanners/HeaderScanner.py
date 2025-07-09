import aiohttp
from scanners.BaseScanner import BaseScanner, ScanResult
from datetime import datetime
from typing import Dict, List, Any

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
    
    async def scn(self, session: aiohttp.ClientSession, url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
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
