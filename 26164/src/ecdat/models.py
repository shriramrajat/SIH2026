"""
Internal Data Models for ECDAT Cryptographic Asset Discovery.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, Union, List
from pathlib import Path
import hashlib
import math
import re


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in probabilities)


def _extract_string_literals(line: str, language: str) -> List[str]:
    literals = []
    in_quote = None
    current_lit = []

    chars = list(line)
    n = len(chars)
    i = 0
    while i < n:
        if in_quote and chars[i] == '\\' and i + 1 < n:
            current_lit.append(chars[i])
            current_lit.append(chars[i+1])
            i += 2
            continue

        if language == "python" and not in_quote:
            if i + 2 < n and line[i:i+3] == '"""':
                in_quote = '"""'
                current_lit = ['"""']
                i += 3
                continue
            elif i + 2 < n and line[i:i+3] == "'''":
                in_quote = "'''"
                current_lit = ["'''"]
                i += 3
                continue

        if language == "python" and in_quote in ['"""', "'''"]:
            target = in_quote
            if i + 2 < n and line[i:i+3] == target:
                current_lit.append(target)
                literals.append("".join(current_lit))
                in_quote = None
                i += 3
                continue
            else:
                current_lit.append(chars[i])
                i += 1
                continue

        if not in_quote:
            if chars[i] in ["'", '"']:
                in_quote = chars[i]
                current_lit = [chars[i]]
                i += 1
                continue
        else:
            current_lit.append(chars[i])
            if chars[i] == in_quote:
                literals.append("".join(current_lit))
                in_quote = None
            i += 1
            continue
        i += 1
    return literals


def is_hardcoded_secret_candidate(literal: str) -> bool:
    val = literal.strip("\"'")
    if len(val) < 8:
        return False

    # Check AWS API keys or other high-entropy formats
    if re.match(r'^AKIA[A-Z0-9]{16}$', val):
        return True

    # Standard secrets typically don't have spaces
    if " " in val:
        return False

    # Standard passwords/keys
    if re.search(r'(?i)(password|passwd|secret|api_key|private_key|token)', val):
        return True

    entropy = calculate_entropy(val)
    if len(val) >= 16 and entropy > 3.8:
        # Check if it has mixed characters to avoid plain text strings
        has_upper = any(c.isupper() for c in val)
        has_lower = any(c.islower() for c in val)
        has_digit = any(c.isdigit() for c in val)
        if (has_upper and has_lower) or (has_lower and has_digit) or (has_upper and has_digit):
            # Exclude paths and URLs
            if "/" not in val and "\\" not in val and ":" not in val:
                return True

    return False


def redact_secret_literal(literal: str) -> str:
    if not literal:
        return literal

    quote = ""
    if literal.startswith("'''") and literal.endswith("'''"):
        quote = "'''"
    elif literal.startswith('"""') and literal.endswith('"""'):
        quote = '"""'
    elif literal.startswith("'") and literal.endswith("'"):
        quote = "'"
    elif literal.startswith('"') and literal.endswith('"'):
        quote = '"'

    val = literal.strip("\"'")
    if len(val) <= 8:
        redacted = "********"
    else:
        redacted = val[:4] + "..." + val[-4:] + " (REDACTED)"
    return f"{quote}{redacted}{quote}"


def _redact_all_secrets_in_text(text: str, language: str) -> str:
    redacted = text
    literals = _extract_string_literals(text, language)
    for lit in literals:
        if is_hardcoded_secret_candidate(lit):
            red = redact_secret_literal(lit)
            redacted = redacted.replace(lit, red)
    return redacted


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

        redacted_snippet = _redact_all_secrets_in_text(code_snippet, language)

        if evidence is None:
            evidence = Evidence(
                code_snippet=redacted_snippet.strip(),
                detection_mechanism=detection_mechanism,
                matched_rule_id=matched_rule_id,
            )
        else:
            evidence.code_snippet = _redact_all_secrets_in_text(evidence.code_snippet, language).strip()

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
