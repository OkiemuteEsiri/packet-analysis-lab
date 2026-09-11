"""Markdown reporting for recruiter-facing synthetic assessments."""
from .analyzer import metrics
from .models import Finding


def render_report(findings: list[Finding]) -> str:
    summary = metrics(findings)
    lines = [
        "# Packet Analysis Assessment",
        "",
        "> Synthetic, offline evidence only. No live traffic was captured or targeted.",
        "",
        "## Executive Summary",
        "",
        f"- Total findings: **{summary['total_findings']}**",
        f"- Highest contextual risk score: **{summary['highest_score']}/100**",
        f"- Severity distribution: `{summary['severity_counts']}`",
        "",
        "## Prioritized Findings",
        "",
        "| ID | Severity | Score | Finding | Source | Destination | ATT&CK |",
        "|---|---:|---:|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(
            f"| `{finding.finding_id}` | {finding.severity} | {finding.score} | "
            f"{finding.title} | `{finding.src_ip}` | `{finding.dst_ip}` | "
            f"{', '.join(finding.attack_techniques) or '-'} |"
        )

    lines.extend(["", "## Remediation and Validation", ""])
    for finding in findings:
        lines.extend([
            f"### {finding.title} — `{finding.finding_id}`",
            "",
            f"**Evidence:** {finding.evidence}",
            "",
            f"**Remediation:** {finding.remediation}",
            "",
            "**Validation:** repeat the same offline assessment against post-change evidence and confirm the original condition is absent without introducing a new control regression.",
            "",
        ])
    return "\n".join(lines)
