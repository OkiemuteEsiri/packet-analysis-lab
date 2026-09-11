"""CLI entry point. Usage: python -m src.cli data/synthetic_flows.json --output reports/generated.md"""
import argparse
from pathlib import Path

from .analyzer import analyze
from .io import load_records
from .report import render_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic network-flow evidence offline")
    parser.add_argument("input", help="JSON file containing synthetic flow records")
    parser.add_argument("--output", help="Optional Markdown report path")
    args = parser.parse_args()

    findings = analyze(load_records(args.input))
    report = render_report(findings)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
        print(f"wrote {len(findings)} findings to {output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
