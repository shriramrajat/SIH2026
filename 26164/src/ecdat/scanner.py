"""
Core Discovery & Scanner Engine for ECDAT.
Recursively scans source files for cryptographic algorithms, libraries, keys, and parameters.
"""

import os
from pathlib import Path
from typing import List, Set, Union, Optional
from ecdat.models import CryptoAsset
from ecdat.rules import REGEX_RULES, RegexRule
from ecdat.ast_parser import scan_python_ast

DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "build",
    "dist",
    ".idea",
    ".vscode",
}

SUPPORTED_EXTENSIONS: Set[str] = {".py", ".java", ".c", ".cpp", ".h", ".hpp", ".pem", ".crt", ".key"}


class Scanner:
    def __init__(self, ignored_dirs: Optional[Set[str]] = None):
        self.ignored_dirs = ignored_dirs or DEFAULT_IGNORED_DIRS

    def discover_files(self, root_path: Union[str, Path]) -> List[Path]:
        """Recursively discover supported source files while respecting ignore list."""
        path = Path(root_path).resolve()
        discovered: List[Path] = []

        if path.is_file():
            if path.suffix.lower() in SUPPORTED_EXTENSIONS:
                return [path]
            return []

        if not path.is_dir():
            return []

        for root, dirs, files in os.walk(path):
            # Exclude ignored directories in-place
            dirs[:] = [d for d in dirs if d not in self.ignored_dirs]

            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    discovered.append(file_path)

        return sorted(discovered)

    def _determine_language(self, file_path: Path) -> str:
        ext = file_path.suffix.lower()
        if ext == ".py":
            return "python"
        elif ext == ".java":
            return "java"
        elif ext in [".c", ".h"]:
            return "c"
        elif ext in [".cpp", ".hpp"]:
            return "cpp"
        return "all"

    def scan_file_regex(self, file_path: Path, content_lines: List[str]) -> List[CryptoAsset]:
        """Scan file content using regular expression rules."""
        language = self._determine_language(file_path)
        assets: List[CryptoAsset] = []

        for idx, line in enumerate(content_lines, start=1):
            stripped_line = line.strip()
            # Skip empty lines or pure single-line comments for performance
            if not stripped_line:
                continue

            for rule in REGEX_RULES:
                # Rule language matching
                if rule.language not in ["all", language]:
                    # Allow 'c' rules for 'cpp' as well
                    if not (rule.language == "c" and language == "cpp"):
                        continue

                match = rule.pattern.search(line)
                if match:
                    algorithm = rule.algorithm
                    category = rule.category
                    library = rule.library
                    key_length = rule.key_length
                    mode = rule.mode
                    padding = rule.padding
                    confidence = rule.confidence

                    # Dynamic parsing for Java rules
                    if rule.rule_id == "java-cipher-instance":
                        transform = match.group(1)
                        parts = transform.split("/")
                        if len(parts) >= 1:
                            algorithm = parts[0].upper()
                            if algorithm in ["RSA", "EC", "DSA", "DH"]:
                                category = "asymmetric_encryption"
                            elif algorithm in ["AES", "DES", "3DES"]:
                                category = "symmetric_encryption"
                        if len(parts) >= 2:
                            mode = parts[1].upper()
                        if len(parts) >= 3:
                            padding = parts[2]

                    elif rule.rule_id == "java-keypair-gen":
                        algo_match = match.group(1).upper()
                        algorithm = "ECC" if algo_match == "EC" else algo_match
                        category = "asymmetric_encryption"

                    elif rule.rule_id == "java-message-digest":
                        algo_match = match.group(1).upper()
                        algorithm = algo_match
                        category = "hashing"

                    # Dynamic parsing for Python RSA.generate regex
                    elif rule.rule_id == "py-crypto-rsa-gen":
                        try:
                            key_length = int(match.group(1))
                        except (IndexError, ValueError):
                            key_length = None

                    asset = CryptoAsset.create(
                        name=f"{algorithm} Detection ({rule.library})",
                        category=category,
                        algorithm=algorithm,
                        file_path=str(file_path),
                        line_number=idx,
                        code_snippet=stripped_line,
                        library=library,
                        confidence=confidence,
                        key_length=key_length,
                        mode=mode,
                        padding=padding,
                    )
                    assets.append(asset)

        return assets

    def scan_file(self, file_path: Path) -> List[CryptoAsset]:
        """Perform full scan on a single file combining AST and Regex detection."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        lines = content.splitlines()
        language = self._determine_language(file_path)

        regex_assets = self.scan_file_regex(file_path, lines)

        # Run AST parser for Python files
        if language == "python":
            ast_assets = scan_python_ast(str(file_path), content)

            # Deduplicate / merge AST and Regex hits on the same line and algorithm
            ast_lines_algos = {(a.line_number, a.algorithm) for a in ast_assets}
            filtered_regex_assets = [
                r for r in regex_assets if (r.line_number, r.algorithm) not in ast_lines_algos
            ]
            return ast_assets + filtered_regex_assets

        return regex_assets

    def scan(self, target_path: Union[str, Path]) -> List[CryptoAsset]:
        """Scan target directory or file and return normalized CryptoAssets."""
        files = self.discover_files(target_path)
        all_assets: List[CryptoAsset] = []

        for file_path in files:
            file_assets = self.scan_file(file_path)
            all_assets.extend(file_assets)

        return all_assets
