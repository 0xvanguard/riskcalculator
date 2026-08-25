#!/usr/bin/env python3
"""
RiskCalculator CLI — Risk Assessment from the command line.

Usage:
    python cli.py cvss --av network --ac low --pr none
    python cli.py epss --cvss 8.5 --exploited
    python cli.py ssvc --severity critical --exploitation active
    python cli.py fair --frequency 5 --magnitude 50000
    python cli.py matrix --likelihood high --impact critical
    python cli.py report --id CVE-2024-1234 --cvss-params '{"attack_vector":"network"}'
    python cli.py batch --file vulns.json
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from calculator import RiskCalculator


rc = RiskCalculator()


def cmd_cvss(args):
    """Calculate CVSS v3.1 score."""
    result = rc.calculate_cvss(
        attack_vector=args.av,
        attack_complexity=args.ac,
        privileges_required=args.pr,
        user_interaction=args.ui,
        scope=args.scope,
        confidentiality=args.c,
        integrity=args.i,
        availability=args.a,
    )

    color = rc.get_severity_color(result.severity)
    bar = rc.get_severity_bar(result.score)

    print(f"\n🎯 CVSS v3.1 Score\n{'='*50}")
    print(f"  Score:       {bar}")
    print(f"  Severity:    {result.severity} ({color})")
    print(f"  Vector:      {result.vector}")
    print(f"  Exploitability: {result.exploitability}")
    print(f"  Impact:      {result.impact}")


def cmd_epss(args):
    """Estimate EPSS score."""
    result = rc.calculate_epss(
        cvss_score=args.cvss,
        known_exploited=args.exploited,
        patched_available=not args.unpatched,
    )

    print(f"\n📊 EPSS Estimation\n{'='*50}")
    print(f"  Probability:  {result.probability:.2%}")
    print(f"  Percentile:   {result.percentile:.0%}")
    print(f"  Label:        {result.label}")
    print(f"\n  {'█' * int(result.probability * 30)}{'░' * (30 - int(result.probability * 30))}")


def cmd_ssvc(args):
    """SSVC decision tree."""
    result = rc.calculate_ssvc(
        cvss_severity=args.severity,
        exploitation_status=args.exploitation,
        system_exposure=args.exposure,
        mission_impact=args.mission,
        technical_impact=args.technical,
    )

    urgency_colors = {"Urgent": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}

    print(f"\n🌲 SSVC Decision\n{'='*50}")
    print(f"  Decision:  {result.decision}")
    print(f"  Urgency:   {urgency_colors.get(result.urgency, '⚪')} {result.urgency}")
    print(f"  Rationale: {result.rationale}")


def cmd_fair(args):
    """FAIR risk analysis."""
    result = rc.fair_analysis(
        loss_event_frequency=args.frequency,
        loss_magnitude=args.magnitude,
    )

    print(f"\n💰 FAIR Analysis\n{'='*50}")
    print(f"  Loss Event Frequency: {result.loss_event_frequency}")
    print(f"  Loss Magnitude:       ${result.loss_magnitude:,.0f}")
    print(f"  ALE (Annual Loss):    ${result.ale:,.0f}")
    print(f"  Risk Level:           {result.risk_level}")
    print(f"  Recommendation:       {result.recommendation}")


def cmd_matrix(args):
    """Risk matrix assessment."""
    result = rc.risk_matrix(
        likelihood=args.likelihood,
        impact=args.impact,
    )

    print(f"\n📐 Risk Matrix\n{'='*50}")
    print(f"  Likelihood:  {result.likelihood}")
    print(f"  Impact:      {result.impact}")
    print(f"  Risk Level:  {result.risk_level} ({result.color})")


def cmd_report(args):
    """Generate full risk report."""
    cvss_params = {}
    if args.cvss_params:
        cvss_params = json.loads(args.cvss_params)

    report = rc.generate_report(
        vuln_id=args.id,
        cvss_params=cvss_params,
        known_exploited=args.exploited,
        exploitation_status=args.exploitation,
        system_exposure=args.exposure,
        mission_impact=args.mission,
        technical_impact=args.technical,
        loss_event_frequency=args.frequency,
        loss_magnitude=args.magnitude,
    )

    color = rc.get_severity_color(report.cvss.severity)
    bar = rc.get_severity_bar(report.cvss.score)

    print(f"\n📋 Risk Report: {report.vuln_id}\n{'='*60}")
    print(f"  CVSS Score:   {bar}")
    print(f"  Severity:     {report.cvss.severity}")
    print(f"  Vector:       {report.cvss.vector}")
    print(f"\n  EPSS:         {report.epss.probability:.2%} ({report.epss.label})")
    print(f"  SSVC:         {report.ssvc.decision} / {report.ssvc.urgency}")
    if report.fair:
        print(f"  FAIR ALE:     ${report.fair.ale:,.0f} ({report.fair.risk_level})")
    print(f"\n  ⚡ Overall Risk: {report.overall_risk}")
    print(f"\n  📌 Recommendations:")
    for rec in report.recommendations:
        print(f"     {rec}")
    print(f"\n  Generated: {report.generated_at}")


def cmd_batch(args):
    """Batch analyze vulnerabilities from JSON file."""
    with open(args.file) as f:
        vulns = json.load(f)

    if isinstance(vulns, dict):
        vulns = vulns.get("vulnerabilities", [vulns])

    reports = rc.batch_analyze(vulns)

    print(f"\n📊 Batch Analysis — {len(reports)} vulnerabilities\n{'='*60}")
    print(f"{'ID':<20} {'CVSS':<8} {'Sev':<10} {'EPSS':<10} {'SSVC':<12} {'Risk'}")
    print("-" * 75)

    for r in reports:
        epss_str = f"{r.epss.probability:.1%}" if r.epss else "N/A"
        ssvc_str = f"{r.ssvc.decision}" if r.ssvc else "N/A"
        print(f"{r.vuln_id:<20} {r.cvss.score:<8} {r.cvss.severity:<10} "
              f"{epss_str:<10} {ssvc_str:<12} {r.overall_risk}")

    # Summary
    risk_counts = {}
    for r in reports:
        risk_counts[r.overall_risk] = risk_counts.get(r.overall_risk, 0) + 1

    print(f"\n  Summary:")
    for level in ["Critical", "High", "Medium", "Low"]:
        count = risk_counts.get(level, 0)
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(level, "⚪")
        print(f"    {icon} {level}: {count}")


def cmd_colors(args):
    """Show CVSS severity colors."""
    print(f"\n🎨 Severity Colors\n{'='*30}")
    for sev in ["None", "Low", "Medium", "High", "Critical"]:
        color = rc.get_severity_color(sev)
        print(f"  {sev:<10} {color}")


def main():
    parser = argparse.ArgumentParser(
        description="🎯 RiskCalculator — Cybersecurity Risk Assessment"
    )
    sub = parser.add_subparsers(dest="command")

    # cvss
    cvss_p = sub.add_parser("cvss", help="Calculate CVSS v3.1")
    cvss_p.add_argument("--av", default="network", choices=["network", "adjacent", "local", "physical"])
    cvss_p.add_argument("--ac", default="low", choices=["low", "high"])
    cvss_p.add_argument("--pr", default="none", choices=["none", "low", "high"])
    cvss_p.add_argument("--ui", default="none", choices=["none", "required"])
    cvss_p.add_argument("--scope", default="unchanged", choices=["unchanged", "changed"])
    cvss_p.add_argument("--c", default="low", choices=["none", "low", "high"])
    cvss_p.add_argument("--i", default="low", choices=["none", "low", "high"])
    cvss_p.add_argument("--a", default="low", choices=["none", "low", "high"])

    # epss
    epss_p = sub.add_parser("epss", help="Estimate EPSS score")
    epss_p.add_argument("--cvss", type=float, required=True)
    epss_p.add_argument("--exploited", action="store_true")
    epss_p.add_argument("--unpatched", action="store_true")

    # ssvc
    ssvc_p = sub.add_parser("ssvc", help="SSVC decision tree")
    ssvc_p.add_argument("--severity", required=True, choices=["none", "low", "medium", "high", "critical"])
    ssvc_p.add_argument("--exploitation", default="none", choices=["none", "poised", "active"])
    ssvc_p.add_argument("--exposure", default="limited", choices=["exposed", "limited", "sealed"])
    ssvc_p.add_argument("--mission", default="minimal", choices=["minimal", "operational", "mission-critical", "essential"])
    ssvc_p.add_argument("--technical", default="low", choices=["low", "medium", "high"])

    # fair
    fair_p = sub.add_parser("fair", help="FAIR risk analysis")
    fair_p.add_argument("--frequency", type=float, required=True)
    fair_p.add_argument("--magnitude", type=float, required=True)

    # matrix
    matrix_p = sub.add_parser("matrix", help="Risk matrix")
    matrix_p.add_argument("--likelihood", required=True, choices=["low", "medium", "high"])
    matrix_p.add_argument("--impact", required=True, choices=["low", "medium", "high", "critical"])

    # report
    report_p = sub.add_parser("report", help="Full risk report")
    report_p.add_argument("--id", default="VULN-001")
    report_p.add_argument("--cvss-params", type=str, default="{}")
    report_p.add_argument("--exploited", action="store_true")
    report_p.add_argument("--exploitation", default="none")
    report_p.add_argument("--exposure", default="limited")
    report_p.add_argument("--mission", default="minimal")
    report_p.add_argument("--technical", default="low")
    report_p.add_argument("--frequency", type=float, default=0)
    report_p.add_argument("--magnitude", type=float, default=0)

    # batch
    batch_p = sub.add_parser("batch", help="Batch analysis")
    batch_p.add_argument("--file", required=True)

    # colors
    sub.add_parser("colors", help="Show severity colors")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    commands = {
        "cvss": cmd_cvss, "epss": cmd_epss, "ssvc": cmd_ssvc,
        "fair": cmd_fair, "matrix": cmd_matrix, "report": cmd_report,
        "batch": cmd_batch, "colors": cmd_colors,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
