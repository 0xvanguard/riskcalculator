"""Tests for RiskCalculator"""

import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.calculator import (
    CVSSScore, EPSSScore, SSVCDecision, FAIRAnalysis,
    RiskMatrix, RiskReport, RiskCalculator
)


rc = RiskCalculator()


def test_cvss_critical():
    result = rc.calculate_cvss(
        attack_vector="network", attack_complexity="low",
        privileges_required="none", user_interaction="none",
        scope="unchanged", confidentiality="high",
        integrity="high", availability="high"
    )
    assert isinstance(result, CVSSScore)
    assert result.score >= 7.0
    assert result.severity in ("High", "Critical")
    assert result.vector.startswith("CVSS:3.1/")
    print(f"✅ CVSS critical: {result.score} ({result.severity})")


def test_cvss_low():
    result = rc.calculate_cvss(
        attack_vector="physical", attack_complexity="high",
        privileges_required="high", user_interaction="required",
        scope="unchanged", confidentiality="none",
        integrity="none", availability="none"
    )
    assert result.score == 0.0
    assert result.severity == "None"
    print(f"✅ CVSS low: {result.score} ({result.severity})")


def test_cvss_medium():
    result = rc.calculate_cvss(
        attack_vector="network", attack_complexity="high",
        privileges_required="low", user_interaction="required",
        scope="unchanged", confidentiality="low",
        integrity="none", availability="none"
    )
    assert result.severity in ("Low", "Medium")
    print(f"✅ CVSS medium: {result.score} ({result.severity})")


def test_cvss_exploitability_positive():
    result = rc.calculate_cvss()
    assert result.exploitability > 0
    assert result.impact >= 0
    print(f"✅ CVSS exploitability: {result.exploitability}, impact: {result.impact}")


def test_epss_high():
    result = rc.calculate_epss(cvss_score=9.5, known_exploited=True)
    assert result.probability > 0.5
    assert result.label in ("High", "Critical")
    print(f"✅ EPSS high: {result.probability:.2%} ({result.label})")


def test_epss_low():
    result = rc.calculate_epss(cvss_score=2.0, known_exploited=False)
    assert result.probability < 0.3
    assert result.label in ("Low", "Medium")
    print(f"✅ EPSS low: {result.probability:.2%} ({result.label})")


def test_epss_to_dict():
    result = rc.calculate_epss(cvss_score=8.0, known_exploited=True)
    d = result.to_dict()
    assert "probability" in d
    assert "percentile" in d
    assert "label" in d
    print("✅ EPSS to_dict OK")


def test_ssvc_critical_exploited():
    result = rc.calculate_ssvc("critical", "active")
    assert result.decision == "Immediate"
    assert result.urgency == "Urgent"
    print(f"✅ SSVC critical+exploited: {result.decision}/{result.urgency}")


def test_ssvc_high_poised():
    result = rc.calculate_ssvc("high", "poised")
    assert result.decision == "Scheduled"
    print(f"✅ SSVC high+poised: {result.decision}")


def test_ssvc_low_defer():
    result = rc.calculate_ssvc("low", "none")
    assert result.decision == "Defer"
    print(f"✅ SSVC low+none: {result.decision}")


def test_fair_critical():
    result = rc.fair_analysis(loss_event_frequency=100, loss_magnitude=50000)
    assert result.ale == 5000000
    assert result.risk_level == "CRITICAL"
    print(f"✅ FAIR critical: ALE=${result.ale:,.0f}")


def test_fair_low():
    result = rc.fair_analysis(loss_event_frequency=1, loss_magnitude=500)
    assert result.ale == 500
    assert result.risk_level == "LOW"
    print(f"✅ FAIR low: ALE=${result.ale:,.0f}")


def test_risk_matrix():
    result = rc.risk_matrix("high", "critical")
    assert result.risk_level == "Critical"
    assert result.color == "#dc2626"
    print(f"✅ Risk matrix: {result.risk_level} ({result.color})")


def test_risk_matrix_low():
    result = rc.risk_matrix("low", "low")
    assert result.risk_level == "Low"
    print(f"✅ Risk matrix low: {result.risk_level}")


def test_generate_report():
    report = rc.generate_report(
        vuln_id="CVE-2024-1234",
        cvss_params={"attack_vector": "network", "confidentiality": "high"},
        known_exploited=True,
        exploitation_status="active",
    )
    assert isinstance(report, RiskReport)
    assert report.vuln_id == "CVE-2024-1234"
    assert report.cvss.score > 0
    assert report.epss is not None
    assert report.ssvc is not None
    assert report.overall_risk in ("Critical", "High", "Medium", "Low")
    assert len(report.recommendations) > 0
    print(f"✅ Report: {report.vuln_id} — {report.overall_risk}")


def test_batch_analyze():
    vulns = [
        {"id": "CVE-001", "cvss_params": {"attack_vector": "network"}, "exploitation_status": "active"},
        {"id": "CVE-002", "cvss_params": {"attack_vector": "local"}, "exploitation_status": "none"},
        {"id": "CVE-003", "cvss_params": {"attack_vector": "network", "confidentiality": "high"}, "known_exploited": True},
    ]
    reports = rc.batch_analyze(vulns)
    assert len(reports) == 3
    assert all(isinstance(r, RiskReport) for r in reports)
    print(f"✅ Batch: {len(reports)} vulnerabilities analyzed")


def test_severity_colors():
    colors = [rc.get_severity_color(s) for s in ["None", "Low", "Medium", "High", "Critical"]]
    assert all(c.startswith("#") for c in colors)
    print(f"✅ Severity colors: {colors}")


def test_severity_bar():
    bar = rc.get_severity_bar(8.5)
    assert "█" in bar
    assert "8.5/10" in bar
    print(f"✅ Severity bar: {bar}")


def test_report_to_dict():
    report = rc.generate_report(vuln_id="TEST-001")
    d = report.to_dict()
    assert d["vuln_id"] == "TEST-001"
    assert "cvss" in d
    assert "epss" in d
    print("✅ Report to_dict OK")


def test_cvss_vector_roundtrip():
    """Test that vector string can be parsed back."""
    original = rc.calculate_cvss(attack_vector="network", scope="changed", confidentiality="high")
    # Parse vector back
    parsed = rc.calculate_cvss_from_vector(original.vector)
    assert parsed.score == original.score
    print(f"✅ CVSS vector roundtrip: {original.score} == {parsed.score}")


if __name__ == "__main__":
    test_cvss_critical()
    test_cvss_low()
    test_cvss_medium()
    test_cvss_exploitability_positive()
    test_epss_high()
    test_epss_low()
    test_epss_to_dict()
    test_ssvc_critical_exploited()
    test_ssvc_high_poised()
    test_ssvc_low_defer()
    test_fair_critical()
    test_fair_low()
    test_risk_matrix()
    test_risk_matrix_low()
    test_generate_report()
    test_batch_analyze()
    test_severity_colors()
    test_severity_bar()
    test_report_to_dict()
    test_cvss_vector_roundtrip()
    print("\n🎉 All 20 tests passed!")
