"""Combine firewall and IDS evidence; simulated blocks only."""
from datetime import datetime, timedelta, timezone


class DecisionEngine:
    def __init__(self, block_seconds=60):
        self.block_seconds = block_seconds
        self.blocked_until = {}

    def decide(self, event, firewall_result, alerts):
        now = datetime.fromisoformat(event["timestamp"])
        source = event["source_ip"]
        expiry = self.blocked_until.get(source)
        if expiry and now < expiry:
            return {"decision": "DENY", "reason": "Source has an active simulated temporary block."}

        high_confidence = any(a["severity"] == "high" for a in alerts)
        if firewall_result["action"] == "DENY":
            return {"decision": "DENY", "reason": "Firewall policy denied the traffic."}
        if high_confidence:
            until = now + timedelta(seconds=self.block_seconds)
            self.blocked_until[source] = until
            return {
                "decision": "DENY",
                "reason": "High-severity IDS evidence; simulated temporary source block.",
                "block_expires": until.isoformat(),
                "requires_admin_review": True,
            }
        if alerts:
            return {"decision": "FLAG", "reason": "IDS alert requires review; traffic not automatically blocked."}
        return {"decision": "ALLOW", "reason": "Firewall allowed traffic and IDS raised no alert."}

    def active_blocks(self, at=None):
        at = at or datetime.now(timezone.utc)
        return {ip: expiry.isoformat() for ip, expiry in self.blocked_until.items() if expiry > at}
