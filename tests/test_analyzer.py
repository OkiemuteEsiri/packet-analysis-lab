import json
import tempfile
import unittest
from pathlib import Path

from src.analyzer import analyze, analyze_flow, metrics
from src.io import load_records
from src.models import FlowRecord
from src.report import render_report


class PacketAnalysisTests(unittest.TestCase):
    def flow(self, **overrides):
        raw = {
            "timestamp": "2026-09-01T00:00:00Z",
            "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20",
            "src_port": 50000, "dst_port": 443,
            "protocol": "HTTPS", "direction": "east-west",
            "bytes_sent": 1000, "packets": 10,
        }
        raw.update(overrides)
        return FlowRecord.from_dict(raw)

    def test_clean_flow_has_no_findings(self):
        self.assertEqual(analyze_flow(self.flow()), [])

    def test_long_dns_query_detected(self):
        f = self.flow(protocol="DNS", dst_port=53, direction="outbound", dns_query="a" * 60)
        findings = analyze_flow(f)
        self.assertEqual(findings[0].title, "Unusually long DNS query")
        self.assertIn("T1071.004", findings[0].attack_techniques)

    def test_large_egress_detected(self):
        f = self.flow(direction="outbound", bytes_sent=5_000_000)
        self.assertTrue(any(x.title == "Large outbound data transfer" for x in analyze_flow(f)))

    def test_unapproved_rdp_detected(self):
        f = self.flow(protocol="RDP", direction="inbound", dst_port=3389, approved_service=False)
        finding = analyze_flow(f)[0]
        self.assertGreaterEqual(finding.score, 70)

    def test_connection_spike_detected(self):
        f = self.flow(direction="inbound", dst_port=443, connection_count=80)
        self.assertTrue(any(x.title == "High connection-attempt concentration" for x in analyze_flow(f)))

    def test_cleartext_http_detected(self):
        f = self.flow(protocol="HTTP", direction="outbound", dst_port=80, http_host="legacy.test")
        self.assertTrue(any(x.title == "Cleartext outbound HTTP" for x in analyze_flow(f)))

    def test_unauthenticated_smb_detected(self):
        f = self.flow(protocol="SMB", dst_port=445, authenticated=False)
        self.assertTrue(any(x.title == "Unauthenticated east-west SMB activity" for x in analyze_flow(f)))

    def test_deterministic_ids(self):
        f = self.flow(protocol="HTTP", direction="outbound", dst_port=80)
        self.assertEqual(analyze_flow(f)[0].finding_id, analyze_flow(f)[0].finding_id)

    def test_scores_are_bounded(self):
        f = self.flow(protocol="RDP", direction="inbound", dst_port=3389,
                      approved_service=False, authenticated=False)
        self.assertTrue(all(0 <= x.score <= 100 for x in analyze_flow(f)))

    def test_findings_are_prioritized(self):
        findings = analyze([
            self.flow(protocol="HTTP", direction="outbound", dst_port=80),
            self.flow(timestamp="2026-09-01T01:00:00Z", protocol="RDP", direction="inbound",
                      dst_port=3389, approved_service=False, authenticated=False),
        ])
        self.assertGreaterEqual(findings[0].score, findings[-1].score)

    def test_metrics(self):
        f = self.flow(protocol="HTTP", direction="outbound", dst_port=80)
        result = metrics(analyze_flow(f))
        self.assertEqual(result["total_findings"], 1)
        self.assertGreater(result["highest_score"], 0)

    def test_report_contains_remediation(self):
        f = self.flow(protocol="HTTP", direction="outbound", dst_port=80)
        report = render_report(analyze_flow(f))
        self.assertIn("Remediation and Validation", report)
        self.assertIn("Cleartext outbound HTTP", report)

    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValueError):
            self.flow(src_ip="not-an-ip")

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            self.flow(dst_port=70000)

    def test_duplicate_records_rejected(self):
        raw = [{
            "timestamp": "2026-09-01T00:00:00Z", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 50000, "dst_port": 443, "protocol": "HTTPS", "direction": "east-west",
            "bytes_sent": 1, "packets": 1
        }]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "flows.json"
            path.write_text(json.dumps(raw + raw), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_records(path)


if __name__ == "__main__":
    unittest.main()
