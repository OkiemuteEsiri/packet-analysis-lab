# Packet Analysis Lab

A defensive **Network Security / Detection Engineering** portfolio project that turns normalized, synthetic packet-flow evidence into explainable security findings, contextual risk scores, MITRE ATT&CK mappings, remediation guidance and repeat-validation reports.

The project is intentionally safe for a public repository: it performs **offline analysis only**. It does not capture traffic, replay packets, scan systems, authenticate to services, modify controls, or target production networks.

## Problem statement

Network telemetry is high-volume and often difficult to translate into remediation work. Raw ports, connection counts and byte volumes are useful only when they are normalized, interpreted in context and converted into decisions an infrastructure or security team can validate.

This lab demonstrates that lifecycle:

```text
Synthetic flow evidence
        |
        v
Fail-closed ingestion + validation
        |
        v
Normalized immutable flow records
        |
        v
Deterministic defensive detections
        |
        v
Contextual 0-100 risk scoring
        |
        +---- MITRE ATT&CK context
        |
        v
Prioritized assessment report
        |
        v
Remediation -> evidence -> repeat validation
```

## What the project demonstrates

- network-flow normalization and input validation;
- defensive detection engineering over structured telemetry;
- transparent, bounded contextual risk scoring;
- deterministic finding IDs suitable for repeat assessment;
- ATT&CK-informed threat context without claiming compromise;
- security reporting for technical and management audiences;
- remediation and post-change validation workflow design;
- unit-testable security analytics;
- least-privilege CI/CD security checks.

## Repository structure

```text
packet-analysis-lab/
├── .github/workflows/ci.yml
├── data/
│   └── synthetic_flows.json
├── docs/
│   └── architecture-methodology.md
├── reports/
│   └── example-assessment.md
├── src/
│   ├── analyzer.py
│   ├── cli.py
│   ├── io.py
│   ├── models.py
│   └── report.py
└── tests/
    └── test_analyzer.py
```

## Detection scenarios

The synthetic dataset intentionally contains both normal and suspicious conditions.

| Scenario | Defensive question | ATT&CK context |
|---|---|---|
| Long DNS query | Does DNS require tunneling/policy triage? | T1048.003, T1071.004 |
| Large outbound transfer | Is unexplained high-volume egress occurring? | T1048 |
| Unapproved inbound RDP | Is an administrative service reachable through an unauthorized path? | T1133, T1021 |
| Connection-attempt concentration | Is a service seeing unusually concentrated connection attempts? | T1110, T1046 |
| Unauthenticated east-west SMB | Is internal SMB bypassing expected authentication controls? | T1021.002 |
| Outbound cleartext HTTP | Is application traffic exposed to cleartext transport risk? | T1040 |

ATT&CK mappings explain why an observed control condition matters. They are **not evidence that an ATT&CK technique was executed**.

## Risk model

Each detection begins with a documented base score. Context can increase priority when activity is:

- outbound;
- unauthenticated;
- associated with an unapproved service path.

Scores are clamped to `0-100` and mapped to severity:

| Score | Severity |
|---:|---|
| 85-100 | Critical |
| 70-84 | High |
| 45-69 | Medium |
| 0-44 | Low |

The model is deliberately explainable. It is a prioritization aid rather than a replacement for analyst judgment or production baselining.

## Example synthetic assessment

The included fictional evidence produces six findings, including:

- unapproved inbound RDP;
- unauthenticated east-west SMB;
- high connection-attempt concentration;
- large outbound HTTPS transfer;
- unusually long DNS query;
- cleartext outbound HTTP.

See [`reports/example-assessment.md`](reports/example-assessment.md) for the recruiter-facing example output.

## Usage

Requires Python 3.11+ and only the standard library.

Run the assessment and print Markdown to stdout:

```bash
python -m src.cli data/synthetic_flows.json
```

Generate a report file:

```bash
python -m src.cli data/synthetic_flows.json --output reports/generated-assessment.md
```

Run unit tests:

```bash
python -m unittest discover -s tests -v
```

## Input validation

`src/io.py` and `src/models.py` treat telemetry as untrusted input. The parser rejects:

- missing required fields;
- invalid source or destination IP addresses;
- ports outside `0-65535`;
- unsupported protocol/direction values;
- negative byte, packet or connection counts;
- duplicate flow records.

Fail-closed validation prevents malformed evidence from silently entering the analysis pipeline.

## Design decisions

### Offline first

Public portfolio code should not create ambiguity about authorization. The analyzer consumes only files supplied explicitly by the user and has no network collection or targeting capability.

### Deterministic findings

Finding IDs are derived from stable flow attributes with SHA-256. Re-running the same evidence therefore produces the same IDs, simplifying remediation tracking and regression validation.

### Transparent thresholds

The project uses deliberately visible thresholds such as a 5 MB outbound-flow condition and an 80-connection concentration condition. These are **lab values**, not universal enterprise recommendations. Production analytics should baseline by application, asset, zone, business process and time window.

### Context before severity

A port number alone is not a vulnerability. Direction, authentication state and whether a service is approved materially alter the priority of a finding.

## Remediation and validation workflow

The project treats remediation as a closed-loop engineering process:

1. **Triage** — establish whether the condition is expected, authorized or anomalous.
2. **Assign** — identify service and control owners.
3. **Remediate** — apply the appropriate segmentation, authentication, TLS, egress or detection-control change.
4. **Collect evidence** — retain change reference, policy/configuration evidence and post-change telemetry.
5. **Repeat validation** — rerun the same assessment logic on post-change evidence.
6. **Close** — confirm the original condition is absent and intended business functionality remains available.

This avoids treating a ticket update or configuration change as sufficient proof of remediation.

## Architecture and trust boundaries

Detailed architecture, trust boundaries, scoring logic, methodology and limitations are documented in [`docs/architecture-methodology.md`](docs/architecture-methodology.md).

Key boundaries are:

- input evidence is untrusted until validated;
- analysis is deterministic and offline;
- reports use normalized synthetic evidence only;
- no packet capture, scanning, credential use or network mutation is implemented.

## Testing

The unit suite currently covers:

- clean-flow behavior;
- long DNS-query detection;
- large outbound transfer detection;
- inbound administrative exposure;
- connection-attempt concentration;
- cleartext HTTP detection;
- unauthenticated SMB detection;
- deterministic IDs;
- bounded scoring;
- finding prioritization;
- metrics;
- report generation;
- invalid IP rejection;
- invalid port rejection;
- duplicate-record rejection.

## CI/CD

GitHub Actions runs with:

```yaml
permissions:
  contents: read
```

The workflow compiles the Python source, executes the unit suite and generates a synthetic assessment. No repository secrets or external targets are required.

## Limitations

This repository deliberately does not claim capabilities it does not implement:

- it analyzes flow summaries rather than full PCAP payloads;
- it does not perform live capture or packet replay;
- thresholds are illustrative and require environment-specific baselining;
- ATT&CK mappings are contextual and do not prove compromise;
- it is not an IDS/IPS replacement;
- synthetic findings are not evidence from an employer or client environment.

## Skills demonstrated

**Network Security:** protocol-aware flow analysis, administrative-service exposure, east-west traffic review, egress analysis and transport-security assessment.

**Detection Engineering:** signal definition, thresholding, contextual enrichment, deterministic prioritization and ATT&CK-aligned detection context.

**Security Engineering:** fail-closed validation, immutable models, bounded scoring, reproducible analysis, CI/CD and unit testing.

**Incident Response:** evidence-driven triage, prioritization, technical reporting and repeat-validation methodology.

**Risk Communication:** separation of observation from conclusion, documented limitations, explicit remediation and measurable closure criteria.

## Roadmap

Planned safe extensions include:

- baseline profiles per network zone and application;
- time-window aggregation for beaconing and burst analysis;
- approved-service inventory correlation;
- asset-criticality enrichment;
- DNS entropy features with explainable thresholds;
- Suricata/Zeek **export parsers** for offline evidence ingestion;
- JSON/SARIF output for CI integration;
- remediation evidence schema and regression comparison reports.

## Safety and data handling

All IP addresses use private or documentation ranges and all hostnames are fictional. The repository contains no client data, employer telemetry, credentials, production targets, exploit payloads or malicious traffic-generation logic.

## License / use

This repository is intended for defensive learning, portfolio demonstration and authorized security-engineering workflows.
