"""
Tests for EXEC-001: VTY Idle Session Timeout Must Be Configured.
"""

from src.compliance.model import ComplianceStatus, Severity
from src.compliance.rules.exec_timeout import ExecTimeoutRule
from src.parsers.cisco import parse_cisco
from src.parsers.juniper import parse_juniper


class TestCiscoExecTimeout:
    def setup_method(self):
        self.rule = ExecTimeoutRule()

    def test_c1_exec_timeout_10_0_pass(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 10 0\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_c2_exec_timeout_5_30_pass(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 5 30\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_c3_exec_timeout_0_0_fail(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 0 0\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        assert len(result.remediations) == 1

    def test_c4_exec_timeout_11_0_fail(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 11 0\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_c5_exec_timeout_20_30_fail(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 20 30\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_c6_malformed_needs_review(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout malformed\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_c7_10_foo_needs_review(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 10 foo\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_c8_missing_exec_timeout_needs_review(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n login local\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_c9_no_vty_sections_needs_review(self):
        config = parse_cisco("hostname R1\ninterface GigabitEthernet0/0\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_c10_two_vty_sections_both_compliant_pass(self):
        config = parse_cisco(
            "hostname R1\n"
            "line vty 0 4\n exec-timeout 10 0\n"
            "line vty 5 15\n exec-timeout 5 0\n"
        )
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_c11_first_compliant_second_disabled_fail(self):
        config = parse_cisco(
            "hostname R1\n"
            "line vty 0 4\n exec-timeout 10 0\n"
            "line vty 5 15\n exec-timeout 0 0\n"
        )
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_c12_first_compliant_second_over_threshold_fail(self):
        config = parse_cisco(
            "hostname R1\n"
            "line vty 0 4\n exec-timeout 10 0\n"
            "line vty 5 15\n exec-timeout 15 0\n"
        )
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_c13_first_compliant_second_missing_needs_review(self):
        config = parse_cisco(
            "hostname R1\n"
            "line vty 0 4\n exec-timeout 10 0\n"
            "line vty 5 15\n login local\n"
        )
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_c14_multiple_vty_sections_with_one_fail_and_one_needs_review_fails(self):
        config = parse_cisco(
            "hostname R1\n"
            "line vty 0 4\n exec-timeout 0 0\n"
            "line vty 5 15\n login local\n"
        )
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_c15_unrelated_vty_directives_do_not_affect_evaluation(self):
        config = parse_cisco(
            "hostname R1\n"
            "line vty 0 4\n"
            " transport input ssh\n"
            " exec-timeout 5 0\n"
            " access-class 10 in\n"
        )
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_c16_evidence_contains_correct_vty_section_name(self):
        config = parse_cisco("hostname R1\nline vty 5 15\n exec-timeout 10 0\n")
        result = self.rule.evaluate(config)
        assert result.evidence[0].section_name == "line vty 5 15"

    def test_c17_evidence_contains_raw_line(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 10 0\n")
        result = self.rule.evaluate(config)
        assert result.evidence[0].raw_lines == (" exec-timeout 10 0",)

    def test_c18_remediation_exists_on_cisco_fail(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 0 0\n")
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        assert len(result.remediations) == 1
        assert result.remediations[0].vendor == "cisco"
        assert "exec-timeout" in result.remediations[0].config_hint


class TestJuniperExecTimeout:
    def setup_method(self):
        self.rule = ExecTimeoutRule()

    def test_j19_idle_timeout_10_pass(self):
        config = parse_juniper('''system {\n login {\n idle-timeout 10;\n }\n}''')
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_j20_idle_timeout_5_pass(self):
        config = parse_juniper('''system {\n login {\n idle-timeout 5;\n }\n}''')
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_j21_idle_timeout_0_fail(self):
        config = parse_juniper('''system {\n login {\n idle-timeout 0;\n }\n}''')
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_j22_idle_timeout_11_fail(self):
        config = parse_juniper('''system {\n login {\n idle-timeout 11;\n }\n}''')
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_j23_malformed_needs_review(self):
        config = parse_juniper('''system {\n login {\n idle-timeout none;\n }\n}''')
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_j24_absent_idle_timeout_needs_review(self):
        config = parse_juniper('''system {\n services {\n ssh;\n }\n}''')
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_j25_system_absent_needs_review(self):
        config = parse_juniper('''interfaces {\n ge-0/0/0;\n}''')
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_j26_unrelated_login_items_do_not_affect_evaluation(self):
        config = parse_juniper(
            '''system {\n login {\n message "Authorized access only";\n idle-timeout 10;\n }\n}'''
        )
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_j27_evidence_contains_raw_line(self):
        config = parse_juniper('''system {\n login {\n idle-timeout 10;\n }\n}''')
        result = self.rule.evaluate(config)
        assert result.evidence[0].raw_lines == (" idle-timeout 10;",)

    def test_j28_remediation_exists_on_juniper_fail(self):
        config = parse_juniper('''system {\n login {\n idle-timeout 0;\n }\n}''')
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        assert len(result.remediations) == 1
        assert result.remediations[0].vendor == "juniper"
        assert "idle-timeout" in result.remediations[0].config_hint


class TestCrossVendorExecTimeout:
    def setup_method(self):
        self.rule = ExecTimeoutRule()

    def test_v29_unsupported_vendor_not_applicable(self):
        config = parse_cisco("hostname R1")
        config.vendor = "arista"
        result = self.rule.evaluate(config)
        assert result.status == ComplianceStatus.NOT_APPLICABLE

    def test_v30_audit_evaluates_exec_timeout(self):
        from src.compliance.engine import audit
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 10 0\n")
        results = audit(config, [self.rule])
        assert len(results) == 1
        assert results[0].control_id == "EXEC-001"

    def test_metadata_populated_consistently(self):
        config = parse_cisco("hostname R1\nline vty 0 4\n exec-timeout 10 0\n")
        result = self.rule.evaluate(config)
        assert result.control_id == "EXEC-001"
        assert result.severity == Severity.HIGH
        assert result.vendor == "cisco"
        assert result.hostname == "R1"
        assert "CIS-IOS-L2-2.1.1" in result.framework_refs
