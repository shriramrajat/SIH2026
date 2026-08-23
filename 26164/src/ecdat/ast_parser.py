"""
Python AST Visitor Engine for Deep Cryptographic Code Analysis.
"""

import ast
from typing import List, Optional
from ecdat.models import CryptoAsset


class PythonASTScanner(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.assets: List[CryptoAsset] = []

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

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
                        key_length=key_length,
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
                        mode=mode,
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
                        )
                    )

        # Continue generic traversal
        self.generic_visit(node)


def scan_python_ast(file_path: str, source_code: str) -> List[CryptoAsset]:
    """Parse Python code using ast module and return list of CryptoAssets."""
    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError:
        return []

    lines = source_code.splitlines()
    visitor = PythonASTScanner(file_path, lines)
    visitor.visit(tree)
    return visitor.assets
