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
    test_deterministic_asset_id,
    test_path_normalization,
    test_structured_evidence,
    test_language_exposure,
    test_comment_filtering,
<<<<<<< HEAD
    test_detection_matrix_core_language_capabilities,
    test_hardcoded_secret_detection_and_redaction,
    test_key_like_strings_are_not_false_positives,
    test_dynamic_generated_values_are_not_hardcoded_secrets,
    test_comment_markers_inside_strings_do_not_hide_active_code,
    test_malformed_source_does_not_abort_regex_detection,
    test_detected_assets_include_required_evidence_fields,
=======
>>>>>>> a71b40e (feat: implement AST-based Python scanner and comment stripping for cryptographic analysis)
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

    def test_09_deterministic_asset_id(self):
        test_deterministic_asset_id()

    def test_10_path_normalization(self):
        test_path_normalization()

    def test_11_structured_evidence(self):
        test_structured_evidence()

    def test_12_language_exposure(self):
        test_language_exposure()

    def test_13_comment_filtering(self):
        test_comment_filtering()

<<<<<<< HEAD
    def test_14_detection_matrix_core_language_capabilities(self):
        test_detection_matrix_core_language_capabilities()

    def test_15_hardcoded_secret_detection_and_redaction(self):
        test_hardcoded_secret_detection_and_redaction()

    def test_16_key_like_strings_are_not_false_positives(self):
        test_key_like_strings_are_not_false_positives()

    def test_17_dynamic_generated_values_are_not_hardcoded_secrets(self):
        test_dynamic_generated_values_are_not_hardcoded_secrets()

    def test_18_comment_markers_inside_strings_do_not_hide_active_code(self):
        test_comment_markers_inside_strings_do_not_hide_active_code()

    def test_19_malformed_source_does_not_abort_regex_detection(self):
        test_malformed_source_does_not_abort_regex_detection()

    def test_20_detected_assets_include_required_evidence_fields(self):
        test_detected_assets_include_required_evidence_fields()

=======
>>>>>>> a71b40e (feat: implement AST-based Python scanner and comment stripping for cryptographic analysis)

if __name__ == "__main__":
    unittest.main(verbosity=2)
