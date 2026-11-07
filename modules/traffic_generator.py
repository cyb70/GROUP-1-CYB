"""Generate deterministic synthetic traffic for offline experiments."""
from datetime import datetime, timedelta, timezone


def generate_events():
    """Return labelled test events; labels are evaluation-only metadata."""
    start = datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)
    events = []

    def add(src, dst, protocol, port, kind, is_attack, offset, **extra):
        event = {
            "event_id": f"EV-{len(events) + 1:03d}",
            "timestamp": (start + timedelta(seconds=offset)).isoformat(),
            "source_ip": src,
            "destination_ip": dst,
            "protocol": protocol,
            "destination_port": port,
            "event_type": kind,
            "ground_truth_attack": is_attack,
        }
        event.update(extra)
        events.append(event)

    # Legitimate web and DNS activity.
    add("192.168.1.10", "203.0.113.10", "TCP", 443, "web_request", False, 1)
    add("192.168.1.11", "203.0.113.11", "TCP", 80, "web_request", False, 2)
    add("192.168.1.12", "192.168.1.1", "UDP", 53, "dns_request", False, 3)

    # Policy violation: SSH attempt from outside the trusted subnet.
    add("198.51.100.25", "192.168.1.20", "TCP", 22, "connection_attempt", True, 4)

    # Port-scan-like behaviour: many destination ports in a short interval.
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]):
        add("203.0.113.77", "192.168.1.20", "TCP", port,
            "connection_attempt", True, 10 + i)

    # Repeated SSH events to demonstrate alert correlation.
    for i in range(4):
        add("198.51.100.25", "192.168.1.20", "TCP", 22,
            "connection_attempt", True, 30 + i)

    # A benign event that can help exercise threshold tuning.
    add("192.168.1.50", "192.168.1.20", "TCP", 8080, "application_request", False, 40)
    return events
