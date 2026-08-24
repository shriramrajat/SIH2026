"""Tests for the PWD-001 Privileged Exec Password Encryption rule."""

import pytest

from src.compliance.model import ComplianceStatus
from src.compliance.rules.pwd_encryption import PwdEncryptionRule
from src.parsers.cisco import parse_cisco
from src.parsers.juniper import parse_juniper


@pytest.fixture
def rule():
    return PwdEncryptionRule()


# ==============================================================================
# CISCO TESTS
# ==============================================================================


def test_cisco_pass_secret_9(rule):
    cfg = parse_cisco("enable secret 9 $9$abCdEf\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS
    assert len(res.evidence) == 1
    assert "secret 9" in res.evidence[0].observed
    assert "$9$abCdEf" not in res.evidence[0].observed
    assert "$9$abCdEf" not in res.evidence[0].raw_lines[0]
    assert "[REDACTED]" in res.evidence[0].raw_lines[0]


def test_cisco_pass_secret_8(rule):
    cfg = parse_cisco("enable secret 8 $8$abCdEf\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_cisco_fail_secret_5(rule):
    cfg = parse_cisco("enable secret 5 $1$abCdEf\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.FAIL
    assert len(res.evidence) == 1
    assert "secret 5" in res.evidence[0].observed
    assert "migrate" in res.remediations[0].guidance.lower()


def test_cisco_fail_secret_7(rule):
    cfg = parse_cisco("enable secret 7 070C28504D10\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.FAIL


def test_cisco_fail_password(rule):
    cfg = parse_cisco("enable password cleartext\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.FAIL


def test_cisco_fail_secret_0(rule):
    cfg = parse_cisco("enable secret 0 cleartext\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.FAIL


def test_cisco_unknown_format(rule):
    cfg = parse_cisco("enable unknown format\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.NEEDS_REVIEW


def test_cisco_missing_enable(rule):
    cfg = parse_cisco("hostname R1\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.NEEDS_REVIEW


def test_cisco_multiple_strong(rule):
    cfg = parse_cisco("enable secret 8 $8$foo\nenable secret 9 $9$bar\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_cisco_multiple_strong_and_weak(rule):
    cfg = parse_cisco("enable secret 9 $9$foo\nenable password weak\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.FAIL
    obs = [e.observed for e in res.evidence]
    assert any("password" in o for o in obs if o)


def test_cisco_multiple_weak(rule):
    cfg = parse_cisco("enable password weak1\nenable password weak2\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.FAIL


def test_cisco_unrelated_ignored(rule):
    cfg = parse_cisco("hostname R1\nlogging host 1.1.1.1\nenable secret 9 $9$x\n")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_cisco_evidence_identifies_directive(rule):
    cfg = parse_cisco("enable secret 5 $1$abc\n")
    res = rule.evaluate(cfg)
    assert "secret 5" in res.evidence[0].observed


def test_cisco_sanitization(rule):
    secret = "MySuperSecretPassword123!"
    cfg = parse_cisco(f"enable password {secret}\n")
    res = rule.evaluate(cfg)
    assert secret not in res.evidence[0].observed
    if res.evidence[0].raw_lines:
        assert secret not in res.evidence[0].raw_lines[0]


# ==============================================================================
# JUNIPER TESTS
# ==============================================================================


def test_juniper_pass_5(rule):
    cfg = parse_juniper('''
system {
    root-authentication {
        encrypted-password "$5$hash";
    }
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_juniper_pass_6(rule):
    cfg = parse_juniper('''
system {
    root-authentication {
        encrypted-password "$6$hash";
    }
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_juniper_pass_8(rule):
    cfg = parse_juniper('''
system {
    root-authentication {
        encrypted-password "$8$hash";
    }
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_juniper_pass_9(rule):
    cfg = parse_juniper('''
system {
    root-authentication {
        encrypted-password "$9$hash";
    }
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_juniper_fail_1(rule):
    cfg = parse_juniper('''
system {
    root-authentication {
        encrypted-password "$1$hash";
    }
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.FAIL


def test_juniper_missing(rule):
    cfg = parse_juniper('''
system {
    host-name J1;
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.NEEDS_REVIEW


def test_juniper_none_value(rule):
    cfg = parse_juniper('''
system {
    root-authentication {
        encrypted-password;
    }
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.NEEDS_REVIEW


def test_juniper_unknown_prefix(rule):
    cfg = parse_juniper('''
system {
    root-authentication {
        encrypted-password "hash";
    }
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.NEEDS_REVIEW


def test_juniper_multiple_strong(rule):
    cfg = parse_juniper('''
system {
    encrypted-password "$5$a";
    encrypted-password "$6$b";
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_juniper_multiple_strong_weak(rule):
    cfg = parse_juniper('''
system {
    encrypted-password "$5$a";
    encrypted-password "$1$b";
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.FAIL


def test_juniper_missing_system(rule):
    cfg = parse_juniper('''
interfaces {
    ge-0/0/0 {
        disable;
    }
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.NEEDS_REVIEW


def test_juniper_unrelated_ignored(rule):
    cfg = parse_juniper('''
system {
    host-name J1;
    encrypted-password "$6$a";
}
''')
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.PASS


def test_juniper_sanitization(rule):
    secret = "super_secret_hash_value"
    cfg = parse_juniper(f'''
system {{
    root-authentication {{
        encrypted-password "$1${secret}";
    }}
}}
''')
    res = rule.evaluate(cfg)
    assert secret not in res.evidence[0].observed
    if res.evidence[0].raw_lines:
        assert secret not in res.evidence[0].raw_lines[0]
    assert "replace" in res.remediations[0].guidance.lower()


# ==============================================================================
# CROSS-VENDOR
# ==============================================================================


def test_unsupported_vendor(rule):
    cfg = parse_cisco("hostname R1\n")
    object.__setattr__(cfg, "vendor", "arista")
    res = rule.evaluate(cfg)
    assert res.status == ComplianceStatus.NOT_APPLICABLE


def test_audit_evaluates_pwd001():
    from src.compliance.engine import audit
    cfg = parse_cisco("enable secret 9 $9$abc\n")
    results = audit(cfg, [PwdEncryptionRule()])
    assert len(results) == 1
    assert results[0].status == ComplianceStatus.PASS
    assert results[0].control_id == "PWD-001"
