"""
Standard Library Test Runner for ECDAT.
"""

import sys
import unittest
from pathlib import Path

# Add src to sys.path
src_dir = Path(__file__).resolve().parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from test_scanner import (
    test_file_discovery,
    test_python_ast_and_regex_detection,
    test_java_detection,
    test_c_detection,
    test_pem_detection,
    test_line_numbers_and_snippets,
    test_clean_code_false_positives,
    test_full_directory_scan,
)


class TestECDATScanner(unittest.TestCase):
    def test_01_file_discovery(self):
        test_file_discovery()

    def test_02_python_ast_and_regex(self):
        test_python_ast_and_regex_detection()

    def test_03_java_detection(self):
        test_java_detection()

    def test_04_c_detection(self):
        test_c_detection()

    def test_05_pem_detection(self):
        test_pem_detection()

    def test_06_line_numbers_and_snippets(self):
        test_line_numbers_and_snippets()

    def test_07_clean_code_false_positives(self):
        test_clean_code_false_positives()

    def test_08_full_directory_scan(self):
        test_full_directory_scan()


if __name__ == "__main__":
    unittest.main(verbosity=2)
