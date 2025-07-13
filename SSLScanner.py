import aiohttp
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any

from scanners.BaseScanner import BaseScanner, ScanResult

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
                title='Website not using HTTPS',
                description='Website uses HTTP protocol, data transmission is not encrypted',
                evidence=f'URL scheme: {parsed_url.scheme}',
                fix_suggestion='Enable HTTPS and configure SSL certificate',
                url=url,
                timestamp=datetime.now().isoformat()
            )
            results.append(result)
        
        return results
