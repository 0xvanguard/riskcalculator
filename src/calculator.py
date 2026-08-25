"""RiskCalculator — Cybersecurity Risk Assessment Toolkit

CVSS v3.1, EPSS, FAIR Analysis, SSVC, and Risk Matrix calculations.
"""

import math
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime


# ─── Data Models ─────────────────────────────────────────────────────

@dataclass
class CVSSScore:
    """CVSS v3.1 score result."""
    score: float
    severity: str
    vector: str
    exploitability: float
    impact: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EPSSScore:
    """EPSS (Exploit Prediction Scoring System) score."""
    probability: float  # 0.0 - 1.0
    percentile: float   # 0.0 - 1.0
    label: str          # "Critical", "High", "Medium", "Low"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SSVCDecision:
    """SSVC (Stakeholder-Specific Vulnerability Categorization) decision."""
    decision: str       # "Immediate", "Out-of-Cycle", "Scheduled", "Defer"
    urgency: str        # "Urgent", "High", "Medium", "Low"
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FAIRAnalysis:
    """FAIR risk analysis result."""
    loss_event_frequency: float
    loss_magnitude: float
    ale: float  # Annual Loss Expectancy
    risk_level: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskMatrix:
    """Risk matrix assessment."""
    likelihood: str
    impact: str
    risk_level: str
    color: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskReport:
    """Comprehensive risk report combining multiple models."""
    vuln_id: str
    cvss: CVSSScore
    epss: Optional[EPSSScore] = None
    ssvc: Optional[SSVCDecision] = None
    fair: Optional[FAIRAnalysis] = None
    risk_matrix: Optional[RiskMatrix] = None
    overall_risk: str = "Medium"
    recommendations: List[str] = field(default_factory=list)
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# ─── Calculator Engine ───────────────────────────────────────────────

class RiskCalculator:
    """
    Cybersecurity risk calculator.

    Supports CVSS v3.1, EPSS, FAIR, SSVC, and risk matrix models.
    """

    CVSS_WEIGHTS = {
        "attack_vector": {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20},
        "attack_complexity": {"low": 0.77, "high": 0.44},
        "privileges_required": {"none": 0.85, "low": 0.62, "high": 0.27},
        "user_interaction": {"none": 0.85, "required": 0.62},
        "scope": {"changed": 1.08, "unchanged": 1.0},
        "confidentiality": {"high": 0.56, "low": 0.22, "none": 0.0},
        "integrity": {"high": 0.56, "low": 0.22, "none": 0.0},
        "availability": {"high": 0.56, "low": 0.22, "none": 0.0},
    }

    SEVERITY_MAP = {
        (0.0, 0.1): "None",
        (0.1, 4.0): "Low",
        (4.0, 7.0): "Medium",
        (7.0, 9.0): "High",
        (9.0, 10.1): "Critical",
    }

    # SSVC Decision Tree
    SSVC_TREE = {
        ("critical", "active", True): ("Immediate", "Urgent", "Exploited critical vuln — patch now"),
        ("critical", "active", False): ("Immediate", "Urgent", "Critical with active exploitation reports"),
        ("critical", "poised", True): ("Immediate", "High", "Critical with PoC available"),
        ("critical", "poised", False): ("Out-of-Cycle", "High", "Critical severity — schedule emergency patch"),
        ("high", "active", True): ("Out-of-Cycle", "High", "High severity with active exploitation"),
        ("high", "active", False): ("Out-of-Cycle", "High", "High severity with exploitation activity"),
        ("high", "poised", True): ("Scheduled", "Medium", "High severity with PoC — patch within 7 days"),
        ("high", "poised", False): ("Scheduled", "Medium", "High severity — patch within 14 days"),
        ("medium", "active", True): ("Scheduled", "Medium", "Medium severity with active exploitation"),
        ("medium", "poiced", False): ("Scheduled", "Low", "Medium severity — standard patch cycle"),
        ("medium", "poised", False): ("Scheduled", "Low", "Medium severity with PoC — standard cycle"),
        ("low", "active", True): ("Scheduled", "Low", "Low severity with exploitation — monitor"),
        ("low", "poised", False): ("Defer", "Low", "Low severity — defer to regular maintenance"),
    }

    def calculate_cvss(self, attack_vector: str = "network",
                       attack_complexity: str = "low",
                       privileges_required: str = "none",
                       user_interaction: str = "none",
                       scope: str = "unchanged",
                       confidentiality: str = "low",
                       integrity: str = "low",
                       availability: str = "low") -> CVSSScore:
        """Calculate CVSS v3.1 base score."""
        av = self.CVSS_WEIGHTS["attack_vector"][attack_vector]
        ac = self.CVSS_WEIGHTS["attack_complexity"][attack_complexity]
        pr = self.CVSS_WEIGHTS["privileges_required"][privileges_required]
        ui = self.CVSS_WEIGHTS["user_interaction"][user_interaction]

        exploitability = 8.22 * av * ac * pr * ui

        c = self.CVSS_WEIGHTS["confidentiality"][confidentiality]
        i = self.CVSS_WEIGHTS["integrity"][integrity]
        a = self.CVSS_WEIGHTS["availability"][availability]

        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))

        if scope == "changed":
            impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            impact = 6.42 * isc_base

        if impact <= 0:
            score = 0.0
        else:
            score = math.ceil(min((exploitability + impact) * 10, 100)) / 10

        severity = self._get_severity(score)

        vector = (
            f"CVSS:3.1/AV:{attack_vector[0].upper()}/AC:{attack_complexity[0].upper()}"
            f"/PR:{privileges_required[0].upper()}/UI:{user_interaction[0].upper()}"
            f"/S:{scope[0].upper()}/C:{confidentiality[0].upper()}"
            f"/I:{integrity[0].upper()}/A:{availability[0].upper()}"
        )

        return CVSSScore(
            score=score,
            severity=severity,
            vector=vector,
            exploitability=round(exploitability, 2),
            impact=round(max(impact, 0), 2),
        )

    def calculate_cvss_from_vector(self, vector: str) -> CVSSScore:
        """Calculate CVSS from a full vector string."""
        parts = {}
        key_map = {
            "AV": "attack_vector", "AC": "attack_complexity",
            "PR": "privileges_required", "UI": "user_interaction",
            "S": "scope", "C": "confidentiality",
            "I": "integrity", "A": "availability",
        }
        # Map abbreviations to full names — handle overlap carefully
        val_map = {
            "N": "network", "A": "adjacent", "L": "local", "P": "physical",
            "U": "unchanged", "C": "changed",
            "R": "required",
            "H": "high", "M": "medium",
        }

        for part in vector.split("/"):
            if ":" in part:
                key, val = part.split(":", 1)
                if key not in key_map:
                    continue  # skip CVSS:3.1 and unknown keys
                full_key = key_map[key]
                full_val = val_map.get(val, val.lower())
                # Resolve ambiguity: H/L/N can mean different things per field
                if full_key == "attack_vector":
                    full_val = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}.get(val, full_val)
                elif full_key == "attack_complexity":
                    full_val = {"L": "low", "H": "high"}.get(val, full_val)
                elif full_key == "privileges_required":
                    full_val = {"N": "none", "L": "low", "H": "high"}.get(val, full_val)
                elif full_key == "user_interaction":
                    full_val = {"N": "none", "R": "required"}.get(val, full_val)
                elif full_key == "scope":
                    full_val = {"U": "unchanged", "C": "changed"}.get(val, full_val)
                elif full_key in ("confidentiality", "integrity", "availability"):
                    full_val = {"N": "none", "L": "low", "H": "high"}.get(val, full_val)
                parts[full_key] = full_val

        return self.calculate_cvss(**parts)

    def calculate_epss(self, cvss_score: float, known_exploited: bool = False,
                       patched_available: bool = True) -> EPSSScore:
        """
        Estimate EPSS score based on CVSS and exploitation status.

        Real EPSS uses ML models — this is a heuristic estimation.
        """
        # Base probability from CVSS
        base_prob = (cvss_score / 10.0) ** 2 * 0.5

        # Boost for known exploitation
        if known_exploited:
            base_prob = min(base_prob * 3.0, 0.95)

        # Reduce if patch is available and widely deployed
        if patched_available and not known_exploited:
            base_prob *= 0.6

        # Clamp
        probability = max(0.01, min(base_prob, 0.99))

        # Estimate percentile
        if probability > 0.7:
            percentile = 0.95
            label = "Critical"
        elif probability > 0.4:
            percentile = 0.80
            label = "High"
        elif probability > 0.15:
            percentile = 0.50
            label = "Medium"
        else:
            percentile = 0.20
            label = "Low"

        return EPSSScore(probability=round(probability, 4),
                         percentile=round(percentile, 2),
                         label=label)

    def calculate_ssvc(self, cvss_severity: str, exploitation_status: str = "none",
                       system_exposure: str = "limited",
                       mission_impact: str = "minimal",
                       technical_impact: str = "low") -> SSVCDecision:
        """
        SSVC decision tree for vulnerability prioritization.

        Args:
            cvss_severity: none, low, medium, high, critical
            exploitation_status: none, poised, active
            system_exposure: exposed, limited, sealed
            mission_impact: minimal, operational, mission-critical, essential
            technical_impact: low, medium, high
        """
        severity_lower = cvss_severity.lower()
        exploit_lower = exploitation_status.lower()

        # Check for exploited
        is_exploited = exploit_lower == "active"

        # Mission criticality boost
        mission_boost = mission_impact in ("mission-critical", "essential")
        exposure_boost = system_exposure == "exposed"
        tech_boost = technical_impact == "high"

        # Decision logic
        if severity_lower == "critical" and is_exploited:
            return SSVCDecision("Immediate", "Urgent", "Critical + exploited = patch NOW")
        elif severity_lower == "critical" and exploit_lower == "poised":
            return SSVCDecision("Immediate", "High", "Critical with PoC available")
        elif severity_lower == "critical":
            return SSVCDecision("Out-of-Cycle", "High", "Critical severity requires urgent attention")
        elif severity_lower == "high" and is_exploited:
            return SSVCDecision("Out-of-Cycle", "High", "High severity + active exploitation")
        elif severity_lower == "high" and (mission_boost or tech_boost):
            return SSVCDecision("Out-of-Cycle", "Medium", "High severity + mission/technical impact")
        elif severity_lower == "high":
            return SSVCDecision("Scheduled", "Medium", "High severity — patch within 14 days")
        elif severity_lower == "medium" and is_exploited:
            return SSVCDecision("Scheduled", "Medium", "Medium + exploited — prioritize")
        elif severity_lower == "medium" and exposure_boost:
            return SSVCDecision("Scheduled", "Low", "Medium + exposed system")
        elif severity_lower == "medium":
            return SSVCDecision("Scheduled", "Low", "Medium severity — standard cycle")
        elif severity_lower == "low" and is_exploited:
            return SSVCDecision("Scheduled", "Low", "Low but exploited — monitor")
        else:
            return SSVCDecision("Defer", "Low", "Low severity — defer to maintenance")

    def fair_analysis(self, loss_event_frequency: float,
                      loss_magnitude: float) -> FAIRAnalysis:
        """Perform FAIR risk analysis."""
        ale = loss_event_frequency * loss_magnitude

        if ale > 1000000:
            risk_level = "CRITICAL"
            recommendation = "Immediate action required. Consider risk transfer or avoidance."
        elif ale > 100000:
            risk_level = "HIGH"
            recommendation = "Priority mitigation needed. Implement controls."
        elif ale > 10000:
            risk_level = "MEDIUM"
            recommendation = "Monitor and implement basic controls."
        else:
            risk_level = "LOW"
            recommendation = "Accept risk or implement cost-effective controls."

        return FAIRAnalysis(
            loss_event_frequency=loss_event_frequency,
            loss_magnitude=loss_magnitude,
            ale=ale,
            risk_level=risk_level,
            recommendation=recommendation,
        )

    def risk_matrix(self, likelihood: str, impact: str) -> RiskMatrix:
        """Assess risk using 5x5 likelihood/impact matrix."""
        matrix = {
            ("low", "low"): ("Low", "#22c55e"),
            ("low", "medium"): ("Low", "#22c55e"),
            ("low", "high"): ("Medium", "#f59e0b"),
            ("low", "critical"): ("Medium", "#f59e0b"),
            ("medium", "low"): ("Low", "#22c55e"),
            ("medium", "medium"): ("Medium", "#f59e0b"),
            ("medium", "high"): ("High", "#ef4444"),
            ("medium", "critical"): ("Critical", "#dc2626"),
            ("high", "low"): ("Medium", "#f59e0b"),
            ("high", "medium"): ("High", "#ef4444"),
            ("high", "high"): ("Critical", "#dc2626"),
            ("high", "critical"): ("Critical", "#dc2626"),
        }

        risk_level, color = matrix.get(
            (likelihood.lower(), impact.lower()), ("Unknown", "#6b7280")
        )

        return RiskMatrix(likelihood=likelihood, impact=impact,
                          risk_level=risk_level, color=color)

    def generate_report(self, vuln_id: str = "VULN-001",
                        cvss_params: Optional[Dict] = None,
                        known_exploited: bool = False,
                        exploitation_status: str = "none",
                        system_exposure: str = "limited",
                        mission_impact: str = "minimal",
                        technical_impact: str = "low",
                        loss_event_frequency: float = 0.0,
                        loss_magnitude: float = 0.0) -> RiskReport:
        """Generate comprehensive risk report."""
        cvss_params = cvss_params or {}
        cvss = self.calculate_cvss(**cvss_params)
        epss = self.calculate_epss(cvss.score, known_exploited)
        ssvc = self.calculate_ssvc(
            cvss.severity, exploitation_status, system_exposure,
            mission_impact, technical_impact
        )

        fair = None
        if loss_event_frequency > 0 and loss_magnitude > 0:
            fair = self.fair_analysis(loss_event_frequency, loss_magnitude)

        # Overall risk based on combined scores
        risk_score = 0
        severity_weights = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        risk_score += severity_weights.get(cvss.severity, 0) * 2.5
        risk_score += epss.probability * 4
        risk_score += {"Immediate": 3, "Out-of-Cycle": 2, "Scheduled": 1, "Defer": 0}.get(ssvc.decision, 0)

        if risk_score > 10:
            overall = "Critical"
        elif risk_score > 7:
            overall = "High"
        elif risk_score > 4:
            overall = "Medium"
        else:
            overall = "Low"

        recommendations = []
        if ssvc.decision == "Immediate":
            recommendations.append("🔴 PATCH IMMEDIATELY — exploitation likely")
        if epss.probability > 0.5:
            recommendations.append(f"⚠️  High exploitation probability ({epss.probability:.1%})")
        if known_exploited:
            recommendations.append("🚨 Known Exploited Vulnerability (KEV) — verify patches")
        if technical_impact == "high":
            recommendations.append("💥 High technical impact — prioritize confidentiality/integrity")
        if system_exposure == "exposed":
            recommendations.append("🌐 Exposed system — consider WAF/IPS rules as interim mitigation")
        if not recommendations:
            recommendations.append("✅ Standard patch cycle — no urgent action needed")

        return RiskReport(
            vuln_id=vuln_id,
            cvss=cvss,
            epss=epss,
            ssvc=ssvc,
            fair=fair,
            overall_risk=overall,
            recommendations=recommendations,
        )

    def batch_analyze(self, vulns: List[Dict[str, Any]]) -> List[RiskReport]:
        """Analyze multiple vulnerabilities at once."""
        reports = []
        for vuln in vulns:
            report = self.generate_report(
                vuln_id=vuln.get("id", "UNKNOWN"),
                cvss_params=vuln.get("cvss_params", {}),
                known_exploited=vuln.get("known_exploited", False),
                exploitation_status=vuln.get("exploitation_status", "none"),
                system_exposure=vuln.get("system_exposure", "limited"),
                mission_impact=vuln.get("mission_impact", "minimal"),
                technical_impact=vuln.get("technical_impact", "low"),
            )
            reports.append(report)
        return reports

    # ─── Helpers ──────────────────────────────────────────────────────

    def _get_severity(self, score: float) -> str:
        for (low, high), sev in self.SEVERITY_MAP.items():
            if low <= score < high:
                return sev
        return "None"

    def get_severity_color(self, severity: str) -> str:
        colors = {
            "None": "#22c55e", "Low": "#22c55e", "Medium": "#f59e0b",
            "High": "#ef4444", "Critical": "#dc2626",
        }
        return colors.get(severity, "#6b7280")

    def get_severity_bar(self, score: float) -> str:
        filled = int(score)
        empty = 10 - filled
        return "█" * filled + "░" * empty + f" {score}/10"

    def __repr__(self) -> str:
        return "RiskCalculator()"
