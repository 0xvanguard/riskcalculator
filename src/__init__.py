"""RiskCalculator — Cybersecurity Risk Assessment Toolkit"""

from .calculator import (
    CVSSScore, FAIRAnalysis, RiskMatrix, RiskCalculator,
    EPSSScore, SSVCDecision, RiskReport
)

__version__ = "2.0.0"
__all__ = [
    "CVSSScore", "FAIRAnalysis", "RiskMatrix", "RiskCalculator",
    "EPSSScore", "SSVCDecision", "RiskReport"
]
