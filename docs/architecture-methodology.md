# Architecture and Methodology

## Purpose

This project demonstrates a defensive packet-analysis workflow without capturing or targeting live traffic. Input is deliberately constrained to synthetic JSON flow records so the analysis is reproducible, reviewable and safe for a public portfolio.

## Architecture

```text
Synthetic flow evidence
        |
        v
  src/io.py  ---- fail-closed validation / duplicate rejection
        |
        v
 src/models.py ---- immutable normalized FlowRecord
        |
        v
src/analyzer.py ---- deterministic detection + contextual 0-100 scoring
        |
        +----> portfolio metrics / ATT&CK context
        |
        v
 src/report.py ---- prioritized Markdown findings
        |
        v
Remediation + repeat-validation workflow
```

## Trust boundaries

1. **Evidence boundary** — JSON input is untrusted. IP addresses, ports, protocol values, directions, numeric fields and duplicates are validated before analysis.
2. **Analysis boundary** — detection functions are pure and deterministic; they do not contact endpoints, resolvers, scanners or external services.
3. **Reporting boundary** — reports contain only normalized synthetic evidence and remediation guidance.
4. **Operational boundary** — this repository does not capture packets, replay traffic, scan systems, authenticate to services or alter network controls.

## Detection methodology

The synthetic scenarios exercise six defensive conditions:

| Control question | Signal | Defensive action |
|---|---|---|
| Is DNS usage anomalous? | unusually long query label | correlate resolver/endpoint telemetry and validate tunneling controls |
| Is data leaving at an unusual volume? | >=5 MB outbound flow | confirm destination, business purpose, DLP and egress policy |
| Are administrative services exposed? | inbound 22/3389/445 marked unapproved | restrict to management paths and strong authentication |
| Is connection concentration abnormal? | >=80 attempts to selected service ports | correlate auth/firewall evidence and tune rate controls |
| Is application traffic cleartext? | outbound HTTP | migrate to TLS and restrict cleartext egress |
| Is east-west SMB unauthenticated? | SMB with unauthenticated context | remove guest/anonymous access and enforce segmentation |

Thresholds are intentionally transparent and are not presented as universal production values. A real environment should baseline traffic by business service, network zone, asset criticality and time window before setting detection thresholds.

## Risk model

Each finding starts with a control-specific base score. Context can add risk for outbound direction, unauthenticated activity and unapproved service exposure. Scores are capped to the inclusive range 0-100 and mapped to severity:

- `85-100`: critical
- `70-84`: high
- `45-69`: medium
- `0-44`: low

The score is a prioritization aid, not a replacement for analyst judgment.

## MITRE ATT&CK context

Mappings are used to explain why a network condition matters; they do **not** assert that a technique occurred.

- `T1133` External Remote Services
- `T1021` Remote Services
- `T1021.002` SMB/Windows Admin Shares
- `T1110` Brute Force
- `T1046` Network Service Discovery
- `T1048` Exfiltration Over Alternative Protocol
- `T1048.003` Exfiltration Over Unencrypted Non-C2 Protocol
- `T1071.004` DNS
- `T1040` Network Sniffing

## Remediation lifecycle

1. **Triage** — validate whether the synthetic condition would be authorized, expected or anomalous in the target policy model.
2. **Assign** — identify service owner and control owner.
3. **Remediate** — apply the least disruptive control change: segmentation, authenticated administration, TLS migration, egress restriction, resolver policy or rate-based detection.
4. **Collect evidence** — capture approved change reference, updated policy/configuration, and a post-change telemetry sample.
5. **Repeat validation** — rerun the same analyzer against the post-change synthetic/approved evidence.
6. **Close** — close only when the original condition is absent and no compensating control regression is introduced.

## Limitations

- Flow summaries do not provide payload semantics or full packet chronology.
- Static thresholds require production-specific baselining before operational use.
- ATT&CK mapping is contextual rather than attribution.
- The project does not claim IDS/IPS efficacy, packet-capture expertise on a live estate, or compromise evidence.
