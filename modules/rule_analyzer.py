"""Conservative pairwise firewall rule analysis for the teaching prototype."""
import ipaddress


def _network_contains(outer, inner):
    try:
        return ipaddress.ip_network(inner, strict=False).subnet_of(
            ipaddress.ip_network(outer, strict=False)
        )
    except ValueError:
        return False


def _ports_overlap(a, b):
    return a == "ANY" or b == "ANY" or int(a) == int(b)


def _protocols_overlap(a, b):
    return a == "ANY" or b == "ANY" or a == b


def _overlap(a, b):
    return (
        ( _network_contains(a["source"], b["source"]) or _network_contains(b["source"], a["source"]) )
        and ( _network_contains(a["destination"], b["destination"]) or _network_contains(b["destination"], a["destination"]) )
        and _protocols_overlap(a["protocol"], b["protocol"])
        and _ports_overlap(a["destination_port"], b["destination_port"])
    )


def _covers(outer, inner):
    return (
        _network_contains(outer["source"], inner["source"])
        and _network_contains(outer["destination"], inner["destination"])
        and (outer["protocol"] == "ANY" or outer["protocol"] == inner["protocol"])
        and (outer["destination_port"] == "ANY" or outer["destination_port"] == inner["destination_port"])
    )


def analyze_rules(rules):
    """Return potential anomalies; recommendations are not applied automatically."""
    ordered = sorted(rules, key=lambda item: int(item["priority"]))
    findings = []
    for index, earlier in enumerate(ordered):
        for later in ordered[index + 1:]:
            if not _overlap(earlier, later):
                continue
            if _covers(earlier, later):
                findings.append({
                    "type": "SHADOWED_RULE", "rule_id": later["id"],
                    "related_rule_id": earlier["id"],
                    "message": f"{later['id']} is fully covered by earlier rule {earlier['id']}.",
                    "recommendation": "Review the later rule; do not delete without policy-owner approval."
                })
            elif earlier["action"] != later["action"]:
                findings.append({
                    "type": "POTENTIAL_CONFLICT", "rule_id": later["id"],
                    "related_rule_id": earlier["id"],
                    "message": f"{earlier['id']} and {later['id']} overlap and specify different actions.",
                    "recommendation": "Review priority and intended policy."
                })
            else:
                findings.append({
                    "type": "OVERLAP", "rule_id": later["id"],
                    "related_rule_id": earlier["id"],
                    "message": f"{earlier['id']} and {later['id']} have overlapping match spaces.",
                    "recommendation": "Check whether both rules are necessary."
                })
    return findings
