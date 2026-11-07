"""Simple local JSON logging for reproducible simulation runs."""
import json
from pathlib import Path


class SimulationLogger:
    def __init__(self, output_dir="data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.output_dir / "events.jsonl"

    def reset(self):
        self.events_path.write_text("", encoding="utf-8")

    def log_event(self, record):
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def write_json(self, filename, value):
        path = self.output_dir / filename
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path
