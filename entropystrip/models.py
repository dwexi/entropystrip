"""
Domain data models and typed telemetry schemas for EntropyStrip.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any


@dataclass
class SectionReport:
    name: str
    virt_size: str
    raw_size: str
    entropy: float
    perms: str
    status: str
    raw_heatmap: str


@dataclass
class TriageDiagnostic:
    filename: str
    path: str
    hashes: Dict[str, str]
    imphash: Optional[str]
    threat_score: int
    verdict: str
    color: str
    is_dotnet: bool
    is_signed: bool
    has_overlay: bool
    overlay_size: int
    total_imports: int
    anomalies: List[str] = field(default_factory=list)
    mitre: List[Tuple[str, str, str]] = field(default_factory=list)
    ep_disasm: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    wx: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "path": self.path,
            "hashes": self.hashes,
            "imphash": self.imphash,
            "threat_score": self.threat_score,
            "verdict": self.verdict,
            "color": self.color,
            "is_dotnet": self.is_dotnet,
            "is_signed": self.is_signed,
            "has_overlay": self.has_overlay,
            "overlay_size": self.overlay_size,
            "total_imports": self.total_imports,
            "anomalies": self.anomalies,
            "mitre": self.mitre,
            "ep_disasm": self.ep_disasm,
            "indicators": self.indicators,
            "sections": self.sections,
            "wx": self.wx,
        }
