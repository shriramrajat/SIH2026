"""Shared pytest fixtures and path configuration for PS 26100 unit tests."""

import os
import sys
import pytest

# Ensure 26100 is in sys.path so 'src' and 'tests' can be imported cleanly
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TESTS_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.compliance.engine import ComplianceEngine
from tests.fixtures.synthetic_tender_bid import (
    get_expected_synthetic_outcomes,
    get_synthetic_bidder_evidence,
    get_synthetic_tender_requirements,
)


@pytest.fixture
def engine():
    """Return a fresh ComplianceEngine instance."""
    return ComplianceEngine()


@pytest.fixture
def synthetic_requirements():
    """Return list of synthetic requirements."""
    return get_synthetic_tender_requirements()


@pytest.fixture
def synthetic_evidence():
    """Return list of synthetic bidder evidence items."""
    return get_synthetic_bidder_evidence()


@pytest.fixture
def expected_outcomes():
    """Return mapping of requirement_id to expected ComplianceStatus."""
    return dict(get_expected_synthetic_outcomes())
