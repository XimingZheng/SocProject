from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, Any, List
from aiohttp import ClientSession

@dataclass
class ScanResult:
    scanner_name: str
    vulnerability_type: str
    risk_level: str
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
    def __init__(self, name: str):
        self.name = name
        self.results = []

    @abstractmethod
    async def scan(self, session: ClientSession, url: str, response_data: Dict[str, Any]) -> List[ScanResult]:
        pass
