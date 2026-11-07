# HIF-IDS: Hybrid Intelligent Firewall and Intrusion Detection System

A Python educational simulation combining:
- ordered firewall filtering (default deny);
- firewall rule anomaly checks (shadowing, overlap and potential conflicts);
- signature and threshold-based behavioural IDS detection;
- alert correlation that consolidates notifications without deleting raw events;
- evidence-based response recommendations and an in-memory temporary block list;
- CSV/JSON logging and a repeatable simulation.

> This is a controlled, offline teaching prototype. It does not capture live traffic, modify OS firewall rules, or provide production-grade network protection.

## Requirements

- Python 3.10+
- No third-party packages are required for the core simulation.

Optional dashboard/reporting libraries can be added later.

## Run

From the repository root:

```bash
python main.py
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

The simulation writes:
- `data/events.jsonl`: all generated events and decisions;
- `data/incidents.json`: correlated incident summaries;
- `data/rule_anomalies.json`: firewall rule analysis results;
- `data/summary.json`: evaluation metrics.

## Project layout

```
config/       Sample firewall rules and IDS signatures
data/         Generated output (ignored by Git)
modules/      Firewall, IDS, correlation and response modules
tests/        Standard-library unit tests
main.py       Simulation entry point
```

## Detection and evaluation notes

The simulator includes ground-truth labels solely to evaluate detection performance. The IDS and response engine do not read those labels when making decisions.

Metrics include true positives, true negatives, false positives, false negatives, detection rate, false-positive rate, false-negative rate and alert-notification reduction. Alert correlation preserves every raw alert in the event log.

The included thresholds and signatures are demonstration values, not validated operational security policies. Tune them using representative, safely collected data before drawing conclusions.

## Safety boundaries

- No packet sniffing or network scanning is performed.
- No real firewall configuration is changed.
- Blocking is simulated in application memory and expires automatically.
- Rule corrections are recommendations only; they are never applied automatically.
- Review all findings before adapting this prototype to any real environment.

## Next development steps

1. Add a Streamlit dashboard.
2. Add PCAP ingestion in an isolated lab.
3. Add formal rule-space analysis and more complete anomaly classification.
4. Evaluate against labelled datasets and document limitations.
