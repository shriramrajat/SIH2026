"""
Internal Data Models for ECDAT Cryptographic Asset Discovery.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, Union
from pathlib import Path
import hashlib


def normalize_relative_path(file_path: Union[str, Path], root_dir: Optional[Union[str, Path]] = None) -> str:
    """
    Normalizes a file path to be relative to root_dir or CWD, using forward slashes.
    Ensures no machine-specific absolute paths (C:\\... or /home/...) remain.
    """
    path = Path(file_path)

    # 1. Try relative to root_dir if specified
    if root_dir:
        try:
            root_abs = Path(root_dir).resolve()
            path_abs = path.resolve()
            return path_abs.relative_to(root_abs).as_posix()
        except ValueError:
            pass

    # 2. Try relative to Current Working Directory (CWD)
    try:
        cwd = Path.cwd().resolve()
        path_abs = path.resolve()
        return path_abs.relative_to(cwd).as_posix()
    except ValueError:
        pass

    # 3. Fallback to posix path
    return path.as_posix()


@dataclass
class Evidence:
    """Structured evidence for a discovered cryptographic asset."""
    code_snippet: str
    detection_mechanism: str  # 'ast', 'regex', 'pem_header'
    matched_rule_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CryptoAsset:
    """Represents a discovered cryptographic asset in source code."""
    asset_id: str
    name: str
    category: str
    algorithm: str
    file_path: str
    line_number: int
    language: str
    library: str
    confidence: float
    evidence: Evidence
    key_length: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None

    @property
    def code_snippet(self) -> str:
        """Backward compatibility property returning the snippet from evidence."""
        return self.evidence.code_snippet if self.evidence else ""

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
        language: str = "python",
        detection_mechanism: str = "regex",
        matched_rule_id: str = "generic-rule",
        evidence: Optional[Evidence] = None,
        key_length: Optional[int] = None,
        mode: Optional[str] = None,
        padding: Optional[str] = None,
        asset_id: Optional[str] = None,
        root_dir: Optional[Union[str, Path]] = None,
    ) -> "CryptoAsset":
        norm_path = normalize_relative_path(file_path, root_dir=root_dir)

        if evidence is None:
            evidence = Evidence(
                code_snippet=code_snippet.strip(),
                detection_mechanism=detection_mechanism,
                matched_rule_id=matched_rule_id,
            )

        if not asset_id:
            raw_key = f"{norm_path}:{line_number}:{algorithm.upper()}:{library.lower()}:{evidence.matched_rule_id}"
            digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
            asset_id = f"crypto-{digest}"

        return cls(
            asset_id=asset_id,
            name=name,
            category=category,
            algorithm=algorithm,
            file_path=norm_path,
            line_number=line_number,
            language=language,
            library=library,
            confidence=round(confidence, 2),
            evidence=evidence,
            key_length=key_length,
            mode=mode,
            padding=padding,
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["code_snippet"] = self.code_snippet
        return d
