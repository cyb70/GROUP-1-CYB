"""Group repeated alerts while preserving every original alert."""
from datetime import datetime


class AlertCorrelator:
    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        self.incidents = {}

    def add(self, alert):
        key = (alert["source_ip"], alert["destination_ip"], alert["category"])
        current = datetime.fromisoformat(alert["timestamp"])
        incident = self.incidents.get(key)
        if incident:
            previous = datetime.fromisoformat(incident["last_seen"])
            if (current - previous).total_seconds() <= self.window_seconds:
                incident["count"] += 1
                incident["last_seen"] = alert["timestamp"]
                incident["event_ids"].append(alert["event_id"])
                if alert["severity"] == "high":
                    incident["severity"] = "high"
                return incident, False
        incident = {
            "incident_id": f"INC-{len(self.incidents) + 1:03d}",
            "source_ip": alert["source_ip"],
            "destination_ip": alert["destination_ip"],
            "category": alert["category"],
            "severity": alert["severity"],
            "first_seen": alert["timestamp"],
            "last_seen": alert["timestamp"],
            "count": 1,
            "event_ids": [alert["event_id"]],
        }
        self.incidents[key] = incident
        return incident, True

    def summaries(self):
        return list(self.incidents.values())
