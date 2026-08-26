"""
Python AST Visitor Engine for Deep Cryptographic Code Analysis.
"""

import ast
from pathlib import Path
from typing import List, Optional, Union
from ecdat.models import CryptoAsset
from ecdat.rules import is_hardcoded_secret_candidate, redact_secret_literal


class PythonASTScanner(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: List[str], root_dir: Optional[Union[str, Path]] = None):
        self.file_path = file_path
        self.source_lines = source_lines
        self.root_dir = root_dir
        self.assets: List[CryptoAsset] = []

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _target_name(self, target: ast.AST) -> Optional[str]:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return None

    def _literal_value(self, value: ast.AST) -> Optional[Union[str, bytes]]:
        if isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
            return value.value
        return None

    def _add_hardcoded_secret(self, node: ast.AST, identifier: str, literal_value: Union[str, bytes]) -> None:
        if not is_hardcoded_secret_candidate(identifier, literal_value):
            return

        snippet = redact_secret_literal(self._get_snippet(node.lineno))
        self.assets.append(
            CryptoAsset.create(
                name="Hardcoded Secret Literal (AST)",
                category="hardcoded_secret",
                algorithm="SECRET",
                file_path=self.file_path,
                line_number=node.lineno,
                code_snippet=snippet,
                library="source-code",
                confidence=0.85,
                language="python",
                detection_mechanism="ast",
                matched_rule_id="py-ast-hardcoded-secret",
                root_dir=self.root_dir,
            )
        )

    def visit_Assign(self, node: ast.Assign):
        literal_value = self._literal_value(node.value)
        if literal_value is not None:
            for target in node.targets:
                identifier = self._target_name(target)
                if identifier:
                    self._add_hardcoded_secret(node, identifier, literal_value)
                    break

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            literal_value = self._literal_value(node.value)
            identifier = self._target_name(node.target)
            if literal_value is not None and identifier:
                self._add_hardcoded_secret(node, identifier, literal_value)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # 1. RSA.generate(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "RSA":
                key_length = None
                confidence = 0.95
                if node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, int):
                        key_length = first_arg.value
                    else:
                        # Dynamic parameter
                        confidence = 0.75

                snippet = self._get_snippet(node.lineno)
                self.assets.append(
                    CryptoAsset.create(
                        name="RSA Key Generation (AST)",
                        category="asymmetric_encryption",
                        algorithm="RSA",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        code_snippet=snippet,
                        library="PyCryptodome",
                        confidence=confidence,
                        language="python",
                        detection_mechanism="ast",
                        matched_rule_id="py-ast-rsa-gen",
                        key_length=key_length,
                        root_dir=self.root_dir,
                    )
                )

        # 2. AES.new(...)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "new":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "AES":
                mode = None
                confidence = 0.95
                # Search for mode argument e.g. AES.MODE_CBC or AES.MODE_GCM
                for arg in node.args + [k.value for k in node.keywords]:
                    if isinstance(arg, ast.Attribute):
                        if arg.attr.startswith("MODE_"):
                            mode = arg.attr.replace("MODE_", "")
                        elif arg.attr in ["CBC", "GCM", "ECB", "CTR"]:
                            mode = arg.attr

                snippet = self._get_snippet(node.lineno)
                self.assets.append(
                    CryptoAsset.create(
                        name="AES Cipher Instantiation (AST)",
                        category="symmetric_encryption",
                        algorithm="AES",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        code_snippet=snippet,
                        library="PyCryptodome",
                        confidence=confidence,
                        language="python",
                        detection_mechanism="ast",
                        matched_rule_id="py-ast-aes-new",
                        mode=mode,
                        root_dir=self.root_dir,
                    )
                )

        # 3. cryptography library: hashes.SHA1(), hashes.SHA256(), etc.
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashes":
                algo_name = node.func.attr
                mapping = {
                    "SHA1": "SHA-1",
                    "SHA256": "SHA-256",
                    "SHA512": "SHA-512",
                    "MD5": "MD5",
                }
                if algo_name in mapping:
                    snippet = self._get_snippet(node.lineno)
                    self.assets.append(
                        CryptoAsset.create(
                            name=f"Cryptography Hash {mapping[algo_name]} (AST)",
                            category="hashing",
                            algorithm=mapping[algo_name],
                            file_path=self.file_path,
                            line_number=node.lineno,
                            code_snippet=snippet,
                            library="cryptography",
                            confidence=0.95,
                            language="python",
                            detection_mechanism="ast",
                            matched_rule_id=f"py-ast-cryptography-{algo_name.lower()}",
                            root_dir=self.root_dir,
                        )
                    )

            # 4. hashlib.sha256(), hashlib.md5(), etc.
            elif node.func.value.id == "hashlib":
                algo_name = node.func.attr.lower()
                mapping = {
                    "md5": "MD5",
                    "sha1": "SHA-1",
                    "sha256": "SHA-256",
                    "sha512": "SHA-512",
                }
                if algo_name in mapping:
                    snippet = self._get_snippet(node.lineno)
                    self.assets.append(
                        CryptoAsset.create(
                            name=f"Hashlib {mapping[algo_name]} (AST)",
                            category="hashing",
                            algorithm=mapping[algo_name],
                            file_path=self.file_path,
                            line_number=node.lineno,
                            code_snippet=snippet,
                            library="hashlib",
                            confidence=0.95,
                            language="python",
                            detection_mechanism="ast",
                            matched_rule_id=f"py-ast-hashlib-{algo_name}",
                            root_dir=self.root_dir,
                        )
                    )

        # Continue generic traversal
        self.generic_visit(node)


def scan_python_ast(
    file_path: str,
    source_code: str,
    root_dir: Optional[Union[str, Path]] = None,
) -> List[CryptoAsset]:
    """Parse Python code using ast module and return list of CryptoAssets."""
    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError:
        return []

    lines = source_code.splitlines()
    visitor = PythonASTScanner(file_path, lines, root_dir=root_dir)
    visitor.visit(tree)
    return visitor.assets
