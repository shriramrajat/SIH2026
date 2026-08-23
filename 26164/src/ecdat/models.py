"""
Internal Data Models for ECDAT Cryptographic Asset Discovery.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import uuid


@dataclass
class CryptoAsset:
    """Represents a discovered cryptographic asset in source code."""
    asset_id: str
    name: str
    category: str
    algorithm: str
    file_path: str
    line_number: int
    code_snippet: str
    library: str
    confidence: float
    key_length: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None

    @classmethod
    def create(
        cls,
        name: str,
        category: str,
        algorithm: str,
        file_path: str,
        line_number: int,
        code_snippet: str,
        library: str,
        confidence: float,
        key_length: Optional[int] = None,
        mode: Optional[str] = None,
        padding: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> "CryptoAsset":
        if not asset_id:
            asset_id = f"crypto-{uuid.uuid4().hex[:8]}"
        return cls(
            asset_id=asset_id,
            name=name,
            category=category,
            algorithm=algorithm,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet.strip(),
            library=library,
            confidence=round(confidence, 2),
            key_length=key_length,
            mode=mode,
            padding=padding,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
