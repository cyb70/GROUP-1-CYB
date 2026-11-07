"""Run the offline HIF-IDS demonstration."""
import json
from pathlib import Path

from modules.traffic_generator import generate_events
from modules.firewall_engine import Firewall
from modules.rule_analyzer import analyze_rules
from modules.ids_engine import IDS
from modules.alert_correlator import AlertCorrelator
from modules.decision_engine import DecisionEngine
from modules.logger import SimulationLogger


ROOT = Path(__file__).resolve().parent


def calculate_metrics(rows):
    tp = sum(r["ground_truth_attack"] and r["detected"] for r in rows)
    tn = sum((not r["ground_truth_attack"]) and (not r["detected"]) for r in rows)
    fp = sum((not r["ground_truth_attack"]) and r["detected"] for r in rows)
    fn = sum(r["ground_truth_attack"] and (not r["detected"]) for r in rows)
    total = len(rows)
    return {
        "events": total, "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "detection_rate_percent": round(100 * tp / (tp + fn), 2) if tp + fn else 0.0,
        "false_positive_rate_percent": round(100 * fp / (fp + tn), 2) if fp + tn else 0.0,
        "false_negative_rate_percent": round(100 * fn / (fn + tp), 2) if fn + tp else 0.0,
    }


def run_simulation():
    with (ROOT / "config" / "firewall_rules.json").open(encoding="utf-8") as handle:
        firewall = Firewall(json.load(handle))
    with (ROOT / "config" / "detection_signatures.json").open(encoding="utf-8") as handle:
        ids = IDS(json.load(handle))

    logger = SimulationLogger(ROOT / "data")
    logger.reset()
    correlator = AlertCorrelator(window_seconds=60)
    decision_engine = DecisionEngine(block_seconds=60)
    rows = []
    notification_count = 0

    for event in generate_events():
        fw = firewall.evaluate(event)
        alerts = ids.inspect(event)
        detected = bool(alerts)
        for alert in alerts:
            _, is_new_incident = correlator.add(alert)
            notification_count += int(is_new_incident)
        decision = decision_engine.decide(event, fw, alerts)
        row = {
            "event": event,
            "firewall": fw,
            "alerts": alerts,
            "decision": decision,
            "ground_truth_attack": event["ground_truth_attack"],
            "detected": detected,
        }
        rows.append(row)
        logger.log_event(row)

    metrics = calculate_metrics(rows)
    metrics["raw_alert_count"] = sum(len(row["alerts"]) for row in rows)
    metrics["correlated_notification_count"] = notification_count
    metrics["notification_reduction_percent"] = round(
        100 * (metrics["raw_alert_count"] - notification_count) / metrics["raw_alert_count"], 2
    ) if metrics["raw_alert_count"] else 0.0

    anomalies = analyze_rules(firewall.rules)
    incidents = correlator.summaries()
    logger.write_json("rule_anomalies.json", anomalies)
    logger.write_json("incidents.json", incidents)
    logger.write_json("summary.json", metrics)

    print("\n=== HIF-IDS SIMULATION SUMMARY ===")
    for key, value in metrics.items():
        print(f"{key}: {value}")
    print(f"Firewall rule findings: {len(anomalies)}")
    print(f"Correlated incidents: {len(incidents)}")
    print(f"Output directory: {ROOT / 'data'}")
    return metrics


if __name__ == "__main__":
    run_simulation()
