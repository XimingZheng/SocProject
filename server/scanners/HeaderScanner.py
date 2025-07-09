import aiohttp
from scanners.BaseScanner import BaseScanner, ScanResult
from datetime import datetime
from typing import Dict, List, Any

class HeaderScanner(BaseScanner):
    """HTTP Response Header Security Scanner"""
    
    def __init__(self):
        super().__init__("Header Scanner")
        self.security_headers = {
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'description': 'Prevent MIME type sniffing attacks',
                'recommended_value': 'nosniff',
                'risk_level': 'medium',
                'explanation': 'This header prevents browsers from guessing MIME types to avoid executing malicious content.',
                'fix_suggestion': 'Add X-Content-Type-Options: nosniff to the server response.'
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'description': 'Prevent Clickjacking attacks',
                'recommended_value': ['DENY', 'SAMEORIGIN'],
                'risk_level': 'high',
                'explanation': 'This header prevents the page from being embedded in iframes to avoid Clickjacking.',
                'fix_suggestion': 'Set X-Frame-Options to DENY or SAMEORIGIN.'
            },
            'content-security-policy': {
                'name': 'Content-Security-Policy',
                'description': 'Prevent XSS and code injection attacks',
                'risk_level': 'high',
                'explanation': 'This header defines the resources allowed on the page to mitigate XSS.',
                'fix_suggestion': 'Configure a proper CSP policy, e.g., default-src \'self\''
            },
            'strict-transport-security': {
                'name': 'Strict-Transport-Security',
                'description': 'Enforce HTTPS connection',
                'risk_level': 'medium',
                'explanation': 'This header forces browsers to use HTTPS to prevent man-in-the-middle attacks.',
                'fix_suggestion': 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains.'
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'description': 'Enable browser XSS protection',
                'recommended_value': '1; mode=block',
                'risk_level': 'low',
                'explanation': 'This header enables browser XSS filter (deprecated but still useful).',
                'fix_suggestion': 'Set X-XSS-Protection: 1; mode=block'
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'description': 'Control referrer information leakage',
                'recommended_value': ['strict-origin-when-cross-origin', 'no-referrer'],
                'risk_level': 'low',
                'explanation': 'This header controls how much referrer information is sent to reduce information leakage.',
                'fix_suggestion': 'Set Referrer-Policy: strict-origin-when-cross-origin.'
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
                    title=f'Missing {header_config["name"]} header',
                    description=header_config['description'],
                    evidence=f'{header_key} header not found in response',
                    fix_suggestion=header_config['fix_suggestion'],
                    url=url,
                    timestamp=datetime.now().isoformat(),
                    details={'header_name': header_key, 'expected_value': header_config.get('recommended_value')}
                )
                results.append(result)
            else:
                # Validate whether the header value is correctly configured
                validation_result = self._validate_header_value(header_key, header_value, header_config)
                if not validation_result['is_valid']:
                    result = ScanResult(
                        scanner_name=self.name,
                        vulnerability_type='Misconfigured Security Header',
                        risk_level=header_config['risk_level'],
                        title=f'{header_config["name"]} is misconfigured',
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
        """Validate response header value"""
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
            has_default_src = 'default-src' in header_value
            has_unsafe = "'unsafe-inline'" in header_value or "'unsafe-eval'" in header_value
            
            if not has_default_src:
                return {'is_valid': False, 'issue': 'Missing default-src directive'}
            if has_unsafe:
                return {'is_valid': False, 'issue': 'Unsafe directive present: unsafe-inline or unsafe-eval'}
            return {'is_valid': True, 'issue': None}
        
        return {'is_valid': True, 'issue': None}
