"""Compliance evaluation handlers."""

try:
    from src.compliance.evaluators.categorical import evaluate_categorical_requirement
    from src.compliance.evaluators.numeric import evaluate_numeric_requirement
    from src.compliance.evaluators.presence import evaluate_presence_requirement
except ImportError:
    from .categorical import evaluate_categorical_requirement
    from .numeric import evaluate_numeric_requirement
    from .presence import evaluate_presence_requirement

__all__ = [
    "evaluate_numeric_requirement",
    "evaluate_categorical_requirement",
    "evaluate_presence_requirement",
]
