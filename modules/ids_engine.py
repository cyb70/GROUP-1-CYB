"""Signature and threshold-based behavioural intrusion detection."""
from collections import defaultdict, deque
from datetime import datetime


class IDS:
    def __init__(self, signatures, scan_threshold=8, window_seconds=10):
        self.signatures = signatures
        self.scan_threshold = scan_threshold
        self.window_seconds = window_seconds
        self.port_history = defaultdict(deque)

    @classmethod
    def from_json(cls, path, **kwargs):
        import json
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle), **kwargs)

    def inspect(self, event):
        alerts = []
        for signature in self.signatures:
            if (signature["protocol"] == event["protocol"]
                    and int(signature["destination_port"]) == int(event["destination_port"])):
                alerts.append({
                    "category": signature["id"],
                    "severity": signature["severity"],
                    "description": signature["description"],
                    "source_ip": event["source_ip"],
                    "destination_ip": event["destination_ip"],
                    "event_id": event["event_id"],
                    "timestamp": event["timestamp"],
                })

        timestamp = datetime.fromisoformat(event["timestamp"])
        history = self.port_history[event["source_ip"]]
        history.append((timestamp, int(event["destination_port"])))
        while history and (timestamp - history[0][0]).total_seconds() > self.window_seconds:
            history.popleft()
        unique_ports = {port for _, port in history}
        if len(unique_ports) >= self.scan_threshold:
            alerts.append({
                "category": "BEHAVIOUR-PORT-SCAN",
                "severity": "high",
                "description": f"Source contacted {len(unique_ports)} different ports within {self.window_seconds}s.",
                "source_ip": event["source_ip"],
                "destination_ip": event["destination_ip"],
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
            })
        return alerts
