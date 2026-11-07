"""Group repeated alerts while preserving every original alert and incident."""
from datetime import datetime


class AlertCorrelator:
    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        self._active = {}
        self._incidents = []

    def add(self, alert):
        key = (alert["source_ip"], alert["destination_ip"], alert["category"])
        current = datetime.fromisoformat(alert["timestamp"])
        incident = self._active.get(key)
        if incident:
            previous = datetime.fromisoformat(incident["last_seen"])
            elapsed = (current - previous).total_seconds()
            if 0 <= elapsed <= self.window_seconds:
                incident["count"] += 1
                incident["last_seen"] = alert["timestamp"]
                incident["event_ids"].append(alert["event_id"])
                if alert["severity"] == "high":
                    incident["severity"] = "high"
                return incident, False

        incident = {
            "incident_id": f"INC-{len(self._incidents) + 1:03d}",
            "source_ip": alert["source_ip"],
            "destination_ip": alert["destination_ip"],
            "category": alert["category"],
            "severity": alert["severity"],
            "first_seen": alert["timestamp"],
            "last_seen": alert["timestamp"],
            "count": 1,
            "event_ids": [alert["event_id"]],
        }
        self._incidents.append(incident)
        self._active[key] = incident
        return incident, True

    def summaries(self):
        return list(self._incidents)
