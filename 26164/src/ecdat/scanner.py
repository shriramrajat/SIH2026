"""
Core Discovery & Scanner Engine for ECDAT.
Recursively scans source files for cryptographic algorithms, libraries, keys, and parameters.
"""

import os
import re
from pathlib import Path
from typing import List, Set, Union, Optional
from ecdat.models import CryptoAsset
from ecdat.rules import (
    REGEX_RULES,
    RegexRule,
    is_hardcoded_secret_candidate,
    redact_secret_literal
)
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


def clean_code_and_mask_strings(content_lines: List[str], language: str) -> tuple[List[str], List[List[bool]]]:
    cleaned_lines = []
    masks = []
    in_block_comment = False
    in_triple_quote = None

    for line in content_lines:
        chars = list(line)
        mask = [False] * len(chars)
        n = len(chars)
        i = 0
        in_line_comment = False
        in_quote = None

        while i < n:
            if in_block_comment:
                if language in ["java", "c", "cpp", "all"] and i + 1 < n and chars[i] == '*' and chars[i+1] == '/':
                    chars[i] = ' '
                    chars[i+1] = ' '
                    in_block_comment = False
                    i += 2
                else:
                    chars[i] = ' '
                    i += 1
                continue

            if in_triple_quote:
                mask[i] = True
                if language == "python" and i + 2 < n and "".join(chars[i:i+3]) == in_triple_quote:
                    mask[i+1] = True
                    mask[i+2] = True
                    in_triple_quote = None
                    i += 3
                else:
                    i += 1
                continue

            if in_line_comment:
                chars[i] = ' '
                i += 1
                continue

            if in_quote:
                mask[i] = True
                if chars[i] == '\\' and i + 1 < n:
                    mask[i+1] = True
                    i += 2
                elif chars[i] == in_quote:
                    in_quote = None
                    i += 1
                else:
                    i += 1
                continue

            if language == "python":
                if chars[i] == '#':
                    in_line_comment = True
                    chars[i] = ' '
                    i += 1
                    continue
                if i + 2 < n and "".join(chars[i:i+3]) in ['"""', "'''"]:
                    in_triple_quote = "".join(chars[i:i+3])
                    mask[i] = True
                    mask[i+1] = True
                    mask[i+2] = True
                    i += 3
                    continue
            else:
                if i + 1 < n and chars[i] == '/' and chars[i+1] == '/':
                    in_line_comment = True
                    chars[i] = ' '
                    chars[i+1] = ' '
                    i += 2
                    continue
                if i + 1 < n and chars[i] == '/' and chars[i+1] == '*':
                    in_block_comment = True
                    chars[i] = ' '
                    chars[i+1] = ' '
                    i += 2
                    continue

            if chars[i] in ['"', "'"]:
                in_quote = chars[i]
                mask[i] = True
                i += 1
                continue

            i += 1

        cleaned_lines.append("".join(chars))
        masks.append(mask)

    return cleaned_lines, masks


class Scanner:
    def __init__(
        self,
        ignored_dirs: Optional[Set[str]] = None,
        root_dir: Optional[Union[str, Path]] = None,
        max_file_size_bytes: int = 10 * 1024 * 1024,
    ):
        self.ignored_dirs = ignored_dirs or DEFAULT_IGNORED_DIRS
        self.root_dir = root_dir
        self.max_file_size_bytes = max_file_size_bytes
        self.errors: List[Dict[str, str]] = []
        self.skipped_files: List[Dict[str, str]] = []

    def discover_files(self, root_path: Union[str, Path], language_filters: Optional[List[str]] = None) -> List[Path]:
        """Recursively discover supported source files while respecting ignore list and language filters."""
        path = Path(root_path).resolve()
        discovered: List[Path] = []

        target_exts = SUPPORTED_EXTENSIONS
        if language_filters:
            lang_ext_map = {
                "python": {".py"},
                "java": {".java"},
                "c": {".c", ".h"},
                "cpp": {".cpp", ".hpp"},
                "pem": {".pem", ".crt", ".key"}
            }
            valid_exts = set()
            for lf in language_filters:
                valid_exts.update(lang_ext_map.get(lf.lower(), set()))
            if valid_exts:
                target_exts = valid_exts

        if path.is_file():
            if path.suffix.lower() in target_exts:
                return [path]
            return []

        if not path.is_dir():
            return []

        for root, dirs, files in os.walk(path):
            # Exclude ignored directories in-place
            dirs[:] = [d for d in dirs if d not in self.ignored_dirs]

            for file in files:
                file_path = Path(root) / file

                if file_path.is_symlink():
                    try:
                        resolved_path = file_path.resolve()
                        if not str(resolved_path).startswith(str(path)):
                            self.skipped_files.append({"file": str(file_path), "reason": "unsafe_symlink"})
                            continue
                    except Exception as e:
                        self.errors.append({"file": str(file_path), "error": f"Symlink resolution failed: {e}"})
                        continue

                if file_path.suffix.lower() in target_exts:
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
        elif ext in [".pem", ".crt", ".key"]:
            return "pem"
        return "all"

    def scan_file_regex(
        self,
        file_path: Path,
        content_lines: List[str],
        root_dir: Optional[Union[str, Path]] = None,
    ) -> List[CryptoAsset]:
        """Scan file content using regular expression rules."""
        language = self._determine_language(file_path)
        assets: List[CryptoAsset] = []
        effective_root = root_dir or self.root_dir

        cleaned_lines, string_masks = clean_code_and_mask_strings(content_lines, language)

        for idx, (original_line, search_line, string_mask) in enumerate(zip(content_lines, cleaned_lines, string_masks), start=1):
            stripped_search = search_line.strip()
            if not stripped_search:
                continue

            for rule in REGEX_RULES:
                # Rule language matching
                if rule.language not in ["all", language]:
                    # Allow 'c' rules for 'cpp' as well
                    if not (rule.language == "c" and language == "cpp"):
                        continue

                for match in rule.pattern.finditer(search_line):
                    if match.start() < len(string_mask) and string_mask[match.start()]:
                        continue

                    algorithm = rule.algorithm
                    category = rule.category
                    library = rule.library
                    key_length = rule.key_length
                    mode = rule.mode
                    padding = rule.padding
                    confidence = rule.confidence
                    detection_mechanism = "pem_header" if library == "PEM" else "regex"
                    code_snippet = original_line.strip()

                    if getattr(rule, "secret_name_group", None) and getattr(rule, "secret_value_group", None):
                        identifier = match.group(rule.secret_name_group)
                        literal_value = match.group(rule.secret_value_group)
                        if not is_hardcoded_secret_candidate(identifier, literal_value):
                            continue
                        code_snippet = redact_secret_literal(code_snippet)

                    # Dynamic parsing for Java rules
                    if rule.rule_id == "java-cipher-instance":
                        transform = match.group(1)
                        parts = transform.split("/")
                        if len(parts) >= 1:
                            algorithm = parts[0].upper()
                            if algorithm == "DESEDE":
                                algorithm = "3DES"

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

                    elif rule.rule_id == "java-keyagreement-instance":
                        algo_match = match.group(1).upper()
                        algorithm = algo_match
                        category = "key_exchange"

                    elif rule.rule_id == "java-signature-instance":
                        algo_match = match.group(1).upper()
                        if "ECDSA" in algo_match:
                            algorithm = "ECDSA"
                        elif "DSA" in algo_match:
                            algorithm = "DSA"
                        elif "RSA" in algo_match:
                            algorithm = "RSA"
                        else:
                            algorithm = algo_match
                        category = "digital_signature"

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
                        code_snippet=code_snippet,
                        library=library,
                        confidence=confidence,
                        language=language,
                        detection_mechanism=detection_mechanism,
                        matched_rule_id=rule.rule_id,
                        key_length=key_length,
                        mode=mode,
                        padding=padding,
                        root_dir=effective_root,
                    )
                    assets.append(asset)

        return assets

    def scan_file(
        self,
        file_path: Path,
        root_dir: Optional[Union[str, Path]] = None,
    ) -> List[CryptoAsset]:
        """Perform full scan on a single file combining AST and Regex detection."""
        effective_root = root_dir or self.root_dir
        try:
            try:
                file_size = os.path.getsize(file_path)
                if file_size > self.max_file_size_bytes:
                    self.skipped_files.append({"file": str(file_path), "reason": "oversized"})
                    return []
            except Exception as e:
                self.errors.append({"file": str(file_path), "error": f"Failed to get file size: {e}"})
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.splitlines()
            language = self._determine_language(file_path)

            regex_assets = self.scan_file_regex(file_path, lines, root_dir=effective_root)

            # Run AST parser for Python files
            if language == "python":
                ast_assets = scan_python_ast(str(file_path), content, root_dir=effective_root)

                # Deduplicate / merge AST and Regex hits on the same line, algorithm, and library
                ast_lines_algos_libs = {(a.line_number, a.algorithm, a.library) for a in ast_assets}
                filtered_regex_assets = [
                    r for r in regex_assets if (r.line_number, r.algorithm, r.library) not in ast_lines_algos_libs
                ]
                return ast_assets + filtered_regex_assets

            return regex_assets
        except Exception as e:
            self.errors.append({"file": str(file_path), "error": str(e)})
            return []

    def scan(self, target_path: Union[str, Path], language_filters: Optional[List[str]] = None) -> List[CryptoAsset]:
        """Scan target directory or file and return normalized CryptoAssets."""
        target = Path(target_path)
        effective_root = self.root_dir or (target if target.is_dir() else target.parent)
        files = self.discover_files(target_path, language_filters=language_filters)
        all_assets: List[CryptoAsset] = []

        for file_path in files:
            file_assets = self.scan_file(file_path, root_dir=effective_root)
            all_assets.extend(file_assets)

        return all_assets
