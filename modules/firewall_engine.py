"""Small ordered-rule firewall simulator with default-deny behaviour."""
import ipaddress


def _ip_matches(value, network):
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def rule_matches(rule, event):
    src_ok = _ip_matches(event["source_ip"], rule["source"])
    dst_ok = _ip_matches(event["destination_ip"], rule["destination"])
    protocol_ok = rule["protocol"] == "ANY" or rule["protocol"] == event["protocol"]
    port_ok = rule["destination_port"] == "ANY" or int(rule["destination_port"]) == int(event["destination_port"])
    return src_ok and dst_ok and protocol_ok and port_ok


class Firewall:
    def __init__(self, rules):
        self.rules = sorted(rules, key=lambda item: int(item["priority"]))

    @classmethod
    def from_json(cls, path):
        import json
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle))

    def evaluate(self, event):
        for rule in self.rules:
            if rule_matches(rule, event):
                return {"action": rule["action"], "rule_id": rule["id"], "reason": rule["description"]}
        return {"action": "DENY", "rule_id": None, "reason": "Implicit default deny"}
