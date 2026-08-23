"""
conftest.py — pytest configuration for the 26155 project.

Adds the 26155/ directory to sys.path so that ``src`` is importable
as a top-level package when running pytest from the repository root:

    python -m pytest 26155/tests/unit/ -v
"""

import sys
from pathlib import Path

# Insert 26155/ into the path so imports like `from src.ingestion.loader import …`
# work without installing the package.
sys.path.insert(0, str(Path(__file__).parent))
