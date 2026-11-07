"""Unit tests for the HIF-IDS prototype (standard library only)."""
import unittest

from modules.firewall_engine import Firewall
from modules.rule_analyzer import analyze_rules
from modules.ids_engine import IDS
from modules.alert_correlator import AlertCorrelator


class HIFIDSTests(unittest.TestCase):
    def setUp(self):
        self.event = {
            "event_id": "EV-001", "timestamp": "2026-11-07T10:00:00+00:00",
            "source_ip": "192.168.1.10", "destination_ip": "192.168.1.20",
            "protocol": "TCP", "destination_port": 443, "event_type": "web_request"
        }

    def test_firewall_first_match_allow(self):
        rules = [
            {"id": "A", "priority": 1, "source": "192.168.1.0/24",
             "destination": "0.0.0.0/0", "protocol": "TCP",
             "destination_port": 443, "action": "ALLOW", "description": "HTTPS"},
            {"id": "D", "priority": 2, "source": "0.0.0.0/0",
             "destination": "0.0.0.0/0", "protocol": "ANY",
             "destination_port": "ANY", "action": "DENY", "description": "Default"}
        ]
        self.assertEqual(Firewall(rules).evaluate(self.event)["action"], "ALLOW")

    def test_firewall_default_deny(self):
        self.assertEqual(Firewall([]).evaluate(self.event)["action"], "DENY")

    def test_shadowed_rule_detected(self):
        rules = [
            {"id": "A", "priority": 1, "source": "0.0.0.0/0",
             "destination": "0.0.0.0/0", "protocol": "ANY",
             "destination_port": "ANY", "action": "DENY"},
            {"id": "B", "priority": 2, "source": "192.168.1.0/24",
             "destination": "0.0.0.0/0", "protocol": "TCP",
             "destination_port": 443, "action": "ALLOW"}
        ]
        self.assertTrue(any(x["type"] == "SHADOWED_RULE" for x in analyze_rules(rules)))

    def test_ids_signature_alert(self):
        ids = IDS([{"id": "SIG-HTTPS", "protocol": "TCP",
                    "destination_port": 443, "severity": "low",
                    "description": "Test signature"}])
        self.assertEqual(len(ids.inspect(self.event)), 1)

    def test_alert_correlation_preserves_count(self):
        correlator = AlertCorrelator()
        alert = {"source_ip": "192.0.2.1", "destination_ip": "192.0.2.2",
                 "category": "TEST", "severity": "medium",
                 "timestamp": "2026-11-07T10:00:00+00:00", "event_id": "EV-1"}
        correlator.add(alert)
        alert2 = dict(alert, event_id="EV-2", timestamp="2026-11-07T10:00:01+00:00")
        _, is_new = correlator.add(alert2)
        self.assertFalse(is_new)
        self.assertEqual(correlator.summaries()[0]["count"], 2)

    def test_new_incident_after_correlation_window_is_preserved(self):
        correlator = AlertCorrelator(window_seconds=5)
        base = {"source_ip": "192.0.2.1", "destination_ip": "192.0.2.2",
                "category": "TEST", "severity": "medium",
                "timestamp": "2026-11-07T10:00:00+00:00", "event_id": "EV-1"}
        correlator.add(base)
        later = dict(base, event_id="EV-2", timestamp="2026-11-07T10:00:10+00:00")
        _, is_new = correlator.add(later)
        self.assertTrue(is_new)
        self.assertEqual(len(correlator.summaries()), 2)
        self.assertEqual([item["count"] for item in correlator.summaries()], [1, 1])


if __name__ == "__main__":
    unittest.main()
