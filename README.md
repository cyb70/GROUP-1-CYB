# HIF-IDS: Hybrid Intelligent Firewall and Intrusion Detection System

A Python educational simulation combining:
- ordered firewall filtering (default deny);
- firewall rule anomaly checks (shadowing, overlap and potential conflicts);
- signature and threshold-based behavioural IDS detection;
- alert correlation that consolidates notifications without deleting raw events;
- evidence-based response recommendations and an in-memory temporary block list;
- JSON logging, repeatable simulation and a Streamlit monitoring dashboard.

> This is a controlled, offline teaching prototype. It does not capture live traffic, modify OS firewall rules, or provide production-grade network protection.

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt` (Streamlit and pandas for the dashboard).

## Install and run

From the repository root:

```bash
python -m pip install -r requirements.txt
python main.py
streamlit run dashboard/app.py
```

Open the local URL printed by Streamlit. Use **Run simulation** in the sidebar to regenerate the synthetic test run and refresh the dashboard.

Run unit tests:

```bash
python -m unittest discover -s tests -v
```

## Simulation outputs

The simulation writes:
- `data/events.jsonl`: all generated events, firewall decisions and IDS alerts;
- `data/incidents.json`: correlated incident summaries;
- `data/rule_anomalies.json`: firewall rule analysis findings;
- `data/summary.json`: evaluation metrics.

The dashboard displays detection metrics, alert correlation, firewall-rule findings, incidents and filterable traffic decisions. It also allows event records to be exported as CSV.

## Project layout

```
config/       Sample firewall rules and IDS signatures
data/         Generated output (ignored by Git)
modules/      Firewall, IDS, correlation and response modules
tests/        Standard-library unit tests
dashboard/    Streamlit monitoring dashboard
main.py       Simulation entry point
```

## Detection and evaluation notes

The simulator includes ground-truth labels solely to evaluate detection performance. The IDS and response engine do not read those labels when making decisions.

Metrics include true positives, true negatives, false positives, false negatives, detection rate, false-positive rate, false-negative rate and alert-notification reduction. Alert correlation preserves raw events and retains separate incidents when a later alert arrives outside the correlation window.

The included thresholds and signatures are demonstration values, not validated operational security policies. Tune them using representative, safely collected data before drawing conclusions. The synthetic simulation is not evidence of real-world detection performance.

## Safety boundaries

- No packet sniffing or network scanning is performed.
- No real firewall configuration is changed.
- Blocking is simulated in application memory and expires automatically.
- Rule corrections are recommendations only; they are never applied automatically.
- Review all findings before adapting this prototype to any real environment.

## Automated validation

GitHub Actions is configured to run unit tests, execute the offline simulation and compile the dashboard on pushes and pull requests to `main`.

## Next development steps

1. Add PCAP ingestion in an isolated lab.
2. Add more complete rule-space analysis and anomaly classification.
3. Evaluate against labelled datasets and document limitations.
4. Expand the dashboard with experiment comparisons and historical runs.
