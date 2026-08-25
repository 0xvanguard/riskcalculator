<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/python-3.10+-yellow?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/tests-20-passing-brightgreen?style=for-the-badge">
  <img src="https://img.shields.io/github/stars/0xvanguard/riskcalculator?style=for-the-badge">
</p>

# 🎯 RiskCalculator

**Cybersecurity Risk Assessment Toolkit — CVSS v3.1, EPSS, FAIR, SSVC, and Risk Matrix.**

RiskCalculator provides comprehensive risk assessment using industry-standard frameworks. Calculate CVSS scores, estimate EPSS exploitation probability, perform FAIR financial risk analysis, make SSVC prioritization decisions, and visualize risk matrices.

## ✨ Features

| Feature | Description |
|---------|-------------|
| **CVSS v3.1** | Full base score calculation with vector parsing |
| **EPSS Estimation** | Exploitation probability based on CVSS + context |
| **SSVC** | Stakeholder-Specific Vulnerability Categorization |
| **FAIR Analysis** | Financial risk (ALE, loss frequency × magnitude) |
| **Risk Matrix** | Likelihood × Impact visual assessment |
| **Full Reports** | Combined multi-framework risk reports |
| **Batch Analysis** | Analyze multiple vulns from JSON |
| **Vector Parsing** | Parse CVSS strings back to scores |
| **Severity Colors** | CSS colors for dashboards |

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# CVSS score
python cli.py cvss --av network --ac low --pr none

# EPSS estimation
python cli.py epss --cvss 9.0 --exploited

# SSVC decision
python cli.py ssvc --severity critical --exploitation active

# FAIR analysis
python cli.py fair --frequency 5 --magnitude 50000

# Risk matrix
python cli.py matrix --likelihood high --impact critical

# Full report
python cli.py report --id CVE-2024-1234 --exploited

# Batch from JSON
python cli.py batch --file vulns.json
```

## 🐍 Python API

```python
from src.calculator import RiskCalculator

rc = RiskCalculator()

# CVSS v3.1
cvss = rc.calculate_cvss(attack_vector="network", confidentiality="high")
print(f"Score: {cvss.score} ({cvss.severity})")

# EPSS
epss = rc.calculate_epss(cvss.score, known_exploited=True)
print(f"Exploitation probability: {epss.probability:.1%}")

# SSVC
ssvc = rc.calculate_ssvc("critical", "active")
print(f"Decision: {ssvc.decision} ({ssvc.urgency})")

# Full report
report = rc.generate_report(
    vuln_id="CVE-2024-1234",
    cvss_params={"attack_vector": "network", "confidentiality": "high"},
    known_exploited=True
)
print(f"Overall risk: {report.overall_risk}")
```

## 📐 Risk Frameworks

| Framework | What It Measures |
|-----------|------------------|
| **CVSS v3.1** | Technical severity of vulnerability |
| **EPSS** | Probability of exploitation in the wild |
| **SSVC** | When to patch based on your context |
| **FAIR** | Financial impact in dollars |
| **Risk Matrix** | Visual likelihood × impact |

## 📁 Structure

```
riskcalculator/
├── src/
│   ├── __init__.py
│   └── calculator.py       # Core engine (CVSS, EPSS, SSVC, FAIR)
├── tests/
│   └── test_calculator.py  # 20 tests
├── cli.py                  # CLI tool
├── requirements.txt
└── README.md
```

## 📄 License

MIT License — see [LICENSE](LICENSE)
